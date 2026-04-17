package graph

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type HostDNSRecord struct {
	Type  string
	Value string
}

type HostPort struct {
	IP           string
	Port         int
	Protocol     string
	Service      string
	Product      string
	Version      string
	TLS          bool
	CertCN       string
	CertNotAfter string
}

type HostPath struct {
	URL         string
	Path        string
	Status      int
	Title       string
	FinalURL    string
	HasRedirect bool
	Notable     string
}

type HostFindingRef struct {
	ID       string
	Severity string
	Title    string
	URL      string
	Type     string
}

type HostMetadata struct {
	ASN       string
	Hosting   string
	TechStack []string
	FirstSeen string
	LastSeen  string
	Tags      []string
}

type HostReport struct {
	Host         string
	PrimaryIP    string
	DNS          []HostDNSRecord
	AlsoResolves []string
	OpenPorts    []HostPort
	Paths        []HostPath
	Findings     []HostFindingRef
	Metadata     HostMetadata
}

type HostReportOptions struct {
	RequireData bool
}

func (c *Client) BuildHostReport(ctx context.Context, host string) (*HostReport, error) {
	return c.BuildHostReportWithOptions(ctx, host, HostReportOptions{RequireData: true})
}

func (c *Client) BuildHostReportWithOptions(ctx context.Context, host string, opts HostReportOptions) (*HostReport, error) {
	host = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(host, ".")))
	if host == "" {
		return nil, fmt.Errorf("host is required")
	}

	session := c.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	report := &HostReport{Host: host}

	if err := c.loadDNS(ctx, session, report); err != nil {
		return nil, err
	}
	if err := c.loadPorts(ctx, session, report); err != nil {
		return nil, err
	}
	if err := c.loadPaths(ctx, session, report); err != nil {
		return nil, err
	}
	if err := c.loadFindings(ctx, session, report); err != nil {
		return nil, err
	}
	if err := c.loadMetadata(ctx, session, report); err != nil {
		return nil, err
	}

	if opts.RequireData && report.Metadata.FirstSeen == "" && len(report.DNS) == 0 && len(report.OpenPorts) == 0 && len(report.Paths) == 0 {
		return nil, fmt.Errorf("host %q not found or has no reportable data", host)
	}

	return report, nil
}

func (c *Client) loadDNS(ctx context.Context, session neo4j.SessionWithContext, report *HostReport) error {
	query := `
MATCH (h:Subdomain {fqdn: $host})
OPTIONAL MATCH (h)-[:CNAME]->(c:Subdomain)
RETURN
  h.first_seen AS first_seen,
  h.last_seen AS last_seen,
  coalesce(h.ips, '') AS ips,
  collect(DISTINCT c.fqdn) AS cnames`

	result, err := session.Run(ctx, query, map[string]any{"host": report.Host})
	if err != nil {
		return fmt.Errorf("load dns: %w", err)
	}
	if !result.Next(ctx) {
		if err := result.Err(); err != nil {
			return fmt.Errorf("load dns: %w", err)
		}
		return nil
	}
	rec := result.Record()

	if v, ok := rec.Get("first_seen"); ok {
		report.Metadata.FirstSeen = fmt.Sprintf("%v", v)
	}
	if v, ok := rec.Get("last_seen"); ok {
		report.Metadata.LastSeen = fmt.Sprintf("%v", v)
	}

	dns := make([]HostDNSRecord, 0)
	primary := ""

	// Parse IPs from the comma-separated ips property.
	if v, ok := rec.Get("ips"); ok {
		ipsStr := strings.TrimSpace(fmt.Sprintf("%v", v))
		if ipsStr != "" && ipsStr != "<nil>" {
			for _, addr := range strings.Split(ipsStr, ",") {
				addr = strings.TrimSpace(addr)
				if addr == "" {
					continue
				}
				rtype := "A"
				if strings.Contains(addr, ":") {
					rtype = "AAAA"
				}
				dns = append(dns, HostDNSRecord{Type: rtype, Value: addr})
				if primary == "" && rtype == "A" {
					primary = addr
				}
			}
		}
	}

	if v, ok := rec.Get("cnames"); ok {
		for _, cname := range toStringSlice(v) {
			if strings.TrimSpace(cname) == "" {
				continue
			}
			dns = append(dns, HostDNSRecord{Type: "CNAME", Value: cname})
		}
	}

	sort.SliceStable(dns, func(i, j int) bool {
		if dns[i].Type == dns[j].Type {
			return dns[i].Value < dns[j].Value
		}
		return dns[i].Type < dns[j].Type
	})
	report.DNS = dedupeDNS(dns)
	report.PrimaryIP = primary

	if _, err := result.Consume(ctx); err != nil {
		return fmt.Errorf("load dns: %w", err)
	}

	othersQ := `
MATCH (h:Subdomain {fqdn: $host})
WHERE h.ips IS NOT NULL AND h.ips <> ''
WITH h, split(h.ips, ',') AS myIPs
MATCH (other:Subdomain)
WHERE other.fqdn <> $host AND other.ips IS NOT NULL
WITH h, myIPs, other, split(other.ips, ',') AS otherIPs
WHERE any(ip IN myIPs WHERE ip IN otherIPs)
RETURN collect(DISTINCT other.fqdn) AS others`
	othersResult, err := session.Run(ctx, othersQ, map[string]any{"host": report.Host})
	if err != nil {
		return fmt.Errorf("load also resolves: %w", err)
	}
	if othersResult.Next(ctx) {
		if v, ok := othersResult.Record().Get("others"); ok {
			report.AlsoResolves = toStringSlice(v)
			sort.Strings(report.AlsoResolves)
		}
	}
	if err := othersResult.Err(); err != nil {
		return fmt.Errorf("load also resolves: %w", err)
	}

	return nil
}

func (c *Client) loadPorts(ctx context.Context, session neo4j.SessionWithContext, report *HostReport) error {
	query := `
MATCH (h:Subdomain {fqdn: $host})-[:HAS_SERVICE]->(svc:Service)
OPTIONAL MATCH (svc)-[:PRESENTS]->(cert:Certificate)
RETURN DISTINCT
  coalesce(svc.ip, '') AS ip,
  toInteger(coalesce(svc.port, 0)) AS port,
  coalesce(svc.protocol, 'tcp') AS protocol,
  coalesce(svc.product, 'unknown') AS service,
  coalesce(svc.product_name, '') AS product_name,
  coalesce(svc.version, '') AS version,
  coalesce(svc.tls, false) AS tls,
  coalesce(cert.subject_cn, '') AS cert_cn,
  coalesce(cert.not_after, '') AS cert_not_after
ORDER BY port ASC`

	result, err := session.Run(ctx, query, map[string]any{"host": report.Host})
	if err != nil {
		return fmt.Errorf("load ports: %w", err)
	}

	var out []HostPort
	for result.Next(ctx) {
		rec := result.Record()
		port := int(toInt64(recordValue(rec, "port")))
		if port == 0 {
			continue
		}
		out = append(out, HostPort{
			IP:           fmt.Sprintf("%v", recordValue(rec, "ip")),
			Port:         port,
			Protocol:     fmt.Sprintf("%v", recordValue(rec, "protocol")),
			Service:      fmt.Sprintf("%v", recordValue(rec, "service")),
			Product:      fmt.Sprintf("%v", recordValue(rec, "product_name")),
			Version:      fmt.Sprintf("%v", recordValue(rec, "version")),
			TLS:          toBool(recordValue(rec, "tls")),
			CertCN:       fmt.Sprintf("%v", recordValue(rec, "cert_cn")),
			CertNotAfter: fmt.Sprintf("%v", recordValue(rec, "cert_not_after")),
		})
	}
	if err := result.Err(); err != nil {
		return fmt.Errorf("load ports: %w", err)
	}

	report.OpenPorts = out
	return nil
}

func (c *Client) loadPaths(ctx context.Context, session neo4j.SessionWithContext, report *HostReport) error {
	query := `
MATCH (h:Subdomain {fqdn: $host})-[:SERVES]->(u:URL)
OPTIONAL MATCH (u)-[:HAS_FINDING]->(f:Finding)
RETURN
  u.url AS url,
  toInteger(coalesce(u.status_code, 0)) AS status,
  coalesce(u.title, '') AS title,
  coalesce(u.final_url, '') AS final_url,
  coalesce(u.has_redirects, false) AS has_redirects,
  collect(DISTINCT coalesce(f.severity, '')) AS severities,
  collect(DISTINCT coalesce(f.title, '')) AS finding_titles
ORDER BY status DESC, url ASC
LIMIT 300`

	result, err := session.Run(ctx, query, map[string]any{"host": report.Host})
	if err != nil {
		return fmt.Errorf("load paths: %w", err)
	}

	var out []HostPath
	for result.Next(ctx) {
		rec := result.Record()
		u := strings.TrimSpace(fmt.Sprintf("%v", recordValue(rec, "url")))
		if u == "" || u == "<nil>" {
			continue
		}
		parsed, _ := url.Parse(u)
		path := "/"
		if parsed != nil && parsed.Path != "" {
			path = parsed.Path
		}
		notable := ""
		for _, sev := range toStringSlice(recordValue(rec, "severities")) {
			if sev == "" {
				continue
			}
			notable = "★ " + strings.ToLower(sev)
			break
		}
		out = append(out, HostPath{
			URL:         u,
			Path:        path,
			Status:      int(toInt64(recordValue(rec, "status"))),
			Title:       strings.TrimSpace(fmt.Sprintf("%v", recordValue(rec, "title"))),
			FinalURL:    strings.TrimSpace(fmt.Sprintf("%v", recordValue(rec, "final_url"))),
			HasRedirect: toBool(recordValue(rec, "has_redirects")),
			Notable:     notable,
		})
	}
	if err := result.Err(); err != nil {
		return fmt.Errorf("load paths: %w", err)
	}

	report.Paths = out
	return nil
}

func (c *Client) loadFindings(ctx context.Context, session neo4j.SessionWithContext, report *HostReport) error {
	query := `
MATCH (h:Subdomain {fqdn: $host})
CALL {
  WITH h
  MATCH (h)-[:HAS_FINDING]->(f:Finding)
  RETURN f, '' AS url
  UNION
  WITH h
  MATCH (h)-[:HAS_SERVICE]->(:Service)-[:HAS_FINDING]->(f:Finding)
  RETURN f, '' AS url
  UNION
  WITH h
  MATCH (h)-[:SERVES]->(u:URL)-[:HAS_FINDING]->(f:Finding)
  RETURN f, u.url AS url
}
RETURN DISTINCT
  f.id AS id,
  coalesce(f.severity, 'info') AS severity,
  coalesce(f.title, '') AS title,
  coalesce(f.type, '') AS type,
  url
ORDER BY
  CASE coalesce(f.severity, 'info')
    WHEN 'critical' THEN 5
    WHEN 'high' THEN 4
    WHEN 'medium' THEN 3
    WHEN 'low' THEN 2
    ELSE 1
  END DESC,
  f.id ASC
LIMIT 100`

	result, err := session.Run(ctx, query, map[string]any{"host": report.Host})
	if err != nil {
		return fmt.Errorf("load findings: %w", err)
	}

	var out []HostFindingRef
	for result.Next(ctx) {
		rec := result.Record()
		out = append(out, HostFindingRef{
			ID:       strings.TrimSpace(fmt.Sprintf("%v", recordValue(rec, "id"))),
			Severity: strings.TrimSpace(fmt.Sprintf("%v", recordValue(rec, "severity"))),
			Title:    strings.TrimSpace(fmt.Sprintf("%v", recordValue(rec, "title"))),
			URL:      strings.TrimSpace(fmt.Sprintf("%v", recordValue(rec, "url"))),
			Type:     strings.TrimSpace(fmt.Sprintf("%v", recordValue(rec, "type"))),
		})
	}
	if err := result.Err(); err != nil {
		return fmt.Errorf("load findings: %w", err)
	}
	report.Findings = out
	return nil
}

func (c *Client) loadMetadata(ctx context.Context, session neo4j.SessionWithContext, report *HostReport) error {
	query := `
MATCH (h:Subdomain {fqdn: $host})
OPTIONAL MATCH (h)-[:HAS_SERVICE]->(svc:Service)
OPTIONAL MATCH (h)-[:SERVES]->(:URL)-[:RUNS]->(t:Technology)
RETURN
  h.first_seen AS first_seen,
  h.last_seen AS last_seen,
  coalesce(h.asn_number, h.asn, '') AS asn,
  coalesce(h.net_provider, h.hosting, '') AS hosting,
  collect(DISTINCT CASE WHEN coalesce(svc.version, '') = '' THEN coalesce(svc.product, '') ELSE coalesce(svc.product, '') + ' ' + svc.version END) AS service_stack,
  collect(DISTINCT CASE WHEN coalesce(t.version, '') = '' THEN coalesce(t.name, '') ELSE coalesce(t.name, '') + ' ' + t.version END) AS web_stack`

	result, err := session.Run(ctx, query, map[string]any{"host": report.Host})
	if err != nil {
		return fmt.Errorf("load metadata: %w", err)
	}
	if !result.Next(ctx) {
		if err := result.Err(); err != nil {
			return fmt.Errorf("load metadata: %w", err)
		}
		return nil
	}
	rec := result.Record()

	if v, ok := rec.Get("first_seen"); ok && report.Metadata.FirstSeen == "" {
		report.Metadata.FirstSeen = fmt.Sprintf("%v", v)
	}
	if v, ok := rec.Get("last_seen"); ok && report.Metadata.LastSeen == "" {
		report.Metadata.LastSeen = fmt.Sprintf("%v", v)
	}

	if v, ok := rec.Get("asn"); ok {
		asn := strings.TrimSpace(fmt.Sprintf("%v", v))
		if asn != "" && asn != "<nil>" {
			report.Metadata.ASN = asn
		}
	}
	if v, ok := rec.Get("hosting"); ok {
		hosting := strings.TrimSpace(fmt.Sprintf("%v", v))
		if hosting != "" && hosting != "<nil>" {
			report.Metadata.Hosting = hosting
		}
	}

	stackSet := make(map[string]bool)
	for _, tech := range append(toStringSlice(recordValue(rec, "service_stack")), toStringSlice(recordValue(rec, "web_stack"))...) {
		tech = strings.TrimSpace(tech)
		if tech == "" {
			continue
		}
		stackSet[tech] = true
	}
	for s := range stackSet {
		report.Metadata.TechStack = append(report.Metadata.TechStack, s)
	}
	sort.Strings(report.Metadata.TechStack)

	tags := []string{"internet-facing"}
	if len(report.OpenPorts) >= 5 {
		tags = append(tags, "broad-attack-surface")
	}
	if len(report.Findings) > 0 {
		tags = append(tags, "findings-present")
	}
	report.Metadata.Tags = tags

	if _, err := result.Consume(ctx); err != nil {
		return fmt.Errorf("load metadata: %w", err)
	}

	return nil
}

func dedupeDNS(in []HostDNSRecord) []HostDNSRecord {
	seen := make(map[string]bool)
	out := make([]HostDNSRecord, 0, len(in))
	for _, r := range in {
		k := r.Type + "|" + r.Value
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, r)
	}
	return out
}

func recordValue(rec *neo4j.Record, key string) any {
	v, _ := rec.Get(key)
	return v
}

func toBool(v any) bool {
	b, ok := v.(bool)
	return ok && b
}
