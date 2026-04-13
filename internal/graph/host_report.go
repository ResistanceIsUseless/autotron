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
OPTIONAL MATCH (h)-[r:RESOLVES_TO]->(ip:IP)
OPTIONAL MATCH (h)-[:CNAME]->(c:Subdomain)
RETURN
  h.first_seen AS first_seen,
  h.last_seen AS last_seen,
  collect(DISTINCT {rtype: coalesce(r.record_type, CASE WHEN ip.address CONTAINS ':' THEN 'AAAA' ELSE 'A' END), addr: ip.address, ptr: coalesce(ip.ptr, '')}) AS resolved,
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
	if v, ok := rec.Get("resolved"); ok {
		if rows, ok := v.([]any); ok {
			for _, row := range rows {
				m, ok := row.(map[string]any)
				if !ok {
					continue
				}
				addr := strings.TrimSpace(fmt.Sprintf("%v", m["addr"]))
				if addr == "" || addr == "<nil>" {
					continue
				}
				rtype := strings.TrimSpace(fmt.Sprintf("%v", m["rtype"]))
				if rtype == "" || rtype == "<nil>" {
					rtype = "A"
				}
				dns = append(dns, HostDNSRecord{Type: rtype, Value: addr})
				if primary == "" && strings.EqualFold(rtype, "A") {
					primary = addr
				}
				ptr := strings.TrimSpace(fmt.Sprintf("%v", m["ptr"]))
				if ptr != "" && ptr != "<nil>" {
					dns = append(dns, HostDNSRecord{Type: "PTR", Value: ptr})
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
MATCH (h:Subdomain {fqdn: $host})-[:RESOLVES_TO]->(ip:IP)<-[:RESOLVES_TO]-(other:Subdomain)
WHERE other.fqdn <> $host
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
MATCH (h:Subdomain {fqdn: $host})-[:RESOLVES_TO]->(ip:IP)-[:HAS_SERVICE]->(svc:Service)
OPTIONAL MATCH (svc)-[:PRESENTS]->(cert:Certificate)
RETURN DISTINCT
  ip.address AS ip,
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
  MATCH (h)-[:RESOLVES_TO]->(:IP)-[:HAS_SERVICE]->(:Service)-[:HAS_FINDING]->(f:Finding)
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
OPTIONAL MATCH (h)-[:RESOLVES_TO]->(ip:IP)
OPTIONAL MATCH (h)-[:RESOLVES_TO]->(:IP)-[:HAS_SERVICE]->(svc:Service)
OPTIONAL MATCH (h)-[:SERVES]->(:URL)-[:RUNS]->(t:Technology)
RETURN
  h.first_seen AS first_seen,
  h.last_seen AS last_seen,
  collect(DISTINCT coalesce(ip.asn, ip.asn_number, ip.as_number, '')) AS asns,
  collect(DISTINCT coalesce(ip.provider, ip.org, ip.hosting, '')) AS hostings,
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

	for _, asn := range toStringSlice(recordValue(rec, "asns")) {
		asn = strings.TrimSpace(asn)
		if asn != "" {
			report.Metadata.ASN = asn
			break
		}
	}
	for _, hosting := range toStringSlice(recordValue(rec, "hostings")) {
		hosting = strings.TrimSpace(hosting)
		if hosting != "" {
			report.Metadata.Hosting = hosting
			break
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
