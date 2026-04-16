package graph

import (
	"context"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type NodeCount struct {
	Label string `json:"label"`
	Count int64  `json:"count"`
}

type JSFileAsset struct {
	JSFileID     string `json:"jsfile_id"`
	URL          string `json:"url"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	LastSeen     string `json:"last_seen"`
	ParentURL    string `json:"parent_url"`
	FindingCount int64  `json:"finding_count"`
	EndpointHint int64  `json:"endpoint_hint"`
}

type ScanRunView struct {
	ID          string `json:"id"`
	Target      string `json:"target"`
	StartedAt   string `json:"started_at"`
	CompletedAt string `json:"completed_at"`
	Status      string `json:"status"`
}

type URLView struct {
	URL        string `json:"url"`
	Host       string `json:"host"`
	StatusCode int64  `json:"status_code"`
	Title      string `json:"title"`
	LastSeen   string `json:"last_seen"`
}

type ServiceView struct {
	Service  string `json:"service"`
	DNSName  string `json:"dns_name"`
	DNSCount int64  `json:"dns_count"`
	IP       string `json:"ip"`
	Port     int64  `json:"port"`
	Product  string `json:"product"`
	TLS      bool   `json:"tls"`
	Server   string `json:"server"`
	Banner   string `json:"banner"`
	LastSeen string `json:"last_seen"`
}

func (c *Client) NodeCounts(ctx context.Context) ([]NodeCount, error) {
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	query := `
MATCH (n)
RETURN labels(n)[0] AS label, count(n) AS count
ORDER BY count DESC, label ASC`

	result, err := session.Run(ctx, query, nil)
	if err != nil {
		return nil, fmt.Errorf("query node counts: %w", err)
	}

	var out []NodeCount
	for result.Next(ctx) {
		rec := result.Record()
		label, _ := rec.Get("label")
		count, _ := rec.Get("count")
		out = append(out, NodeCount{
			Label: fmt.Sprintf("%v", label),
			Count: toInt64(count),
		})
	}
	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("query node counts: %w", err)
	}

	return out, nil
}

func (c *Client) ListJSFiles(ctx context.Context, limit int) ([]JSFileAsset, error) {
	if limit <= 0 {
		limit = 100
	}

	session := c.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	query := `
MATCH (j:JSFile)
OPTIONAL MATCH (u:URL)-[:LOADS]->(j)
OPTIONAL MATCH (j)-[:HAS_FINDING]->(f:Finding)
OPTIONAL MATCH (u)-[:EXPOSES]->(e:Endpoint)
RETURN
  coalesce(j.jsfile_id, '') AS jsfile_id,
  coalesce(j.url, '') AS url,
  coalesce(j.sha256, '') AS sha256,
  toInteger(coalesce(j.size, 0)) AS size,
  coalesce(j.last_seen, '') AS last_seen,
  coalesce(head(collect(DISTINCT u.url)), '') AS parent_url,
  count(DISTINCT f) AS finding_count,
  count(DISTINCT e) AS endpoint_hint
ORDER BY last_seen DESC
LIMIT $limit`

	result, err := session.Run(ctx, query, map[string]any{"limit": limit})
	if err != nil {
		return nil, fmt.Errorf("query js files: %w", err)
	}

	var out []JSFileAsset
	for result.Next(ctx) {
		rec := result.Record()
		asset := JSFileAsset{}
		if v, ok := rec.Get("jsfile_id"); ok {
			asset.JSFileID = fmt.Sprintf("%v", v)
		}
		if v, ok := rec.Get("url"); ok {
			asset.URL = fmt.Sprintf("%v", v)
		}
		if v, ok := rec.Get("sha256"); ok {
			asset.SHA256 = fmt.Sprintf("%v", v)
		}
		if v, ok := rec.Get("size"); ok {
			asset.Size = toInt64(v)
		}
		if v, ok := rec.Get("last_seen"); ok {
			asset.LastSeen = fmt.Sprintf("%v", v)
		}
		if v, ok := rec.Get("parent_url"); ok {
			asset.ParentURL = fmt.Sprintf("%v", v)
		}
		if v, ok := rec.Get("finding_count"); ok {
			asset.FindingCount = toInt64(v)
		}
		if v, ok := rec.Get("endpoint_hint"); ok {
			asset.EndpointHint = toInt64(v)
		}
		out = append(out, asset)
	}
	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("query js files: %w", err)
	}

	return out, nil
}

func (c *Client) ListScanRuns(ctx context.Context, limit int) ([]ScanRunView, error) {
	if limit <= 0 {
		limit = 50
	}

	session := c.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	query := `
MATCH (r:ScanRun)
RETURN
  coalesce(r.id, '') AS id,
  coalesce(r.target, '') AS target,
  coalesce(r.started_at, '') AS started_at,
  coalesce(r.completed_at, '') AS completed_at,
  coalesce(r.status, '') AS status
ORDER BY started_at DESC
LIMIT $limit`

	result, err := session.Run(ctx, query, map[string]any{"limit": limit})
	if err != nil {
		return nil, fmt.Errorf("query scan runs: %w", err)
	}

	var out []ScanRunView
	for result.Next(ctx) {
		rec := result.Record()
		out = append(out, ScanRunView{
			ID:          fmt.Sprintf("%v", recordValue(rec, "id")),
			Target:      fmt.Sprintf("%v", recordValue(rec, "target")),
			StartedAt:   fmt.Sprintf("%v", recordValue(rec, "started_at")),
			CompletedAt: fmt.Sprintf("%v", recordValue(rec, "completed_at")),
			Status:      fmt.Sprintf("%v", recordValue(rec, "status")),
		})
	}
	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("query scan runs: %w", err)
	}

	return out, nil
}

func (c *Client) ListURLs(ctx context.Context, limit int) ([]URLView, error) {
	if limit <= 0 {
		limit = 100
	}

	session := c.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	query := `
MATCH (u:URL)
RETURN
  coalesce(u.url, '') AS url,
  coalesce(u.host, '') AS host,
  toInteger(coalesce(u.status_code, 0)) AS status_code,
  coalesce(u.title, '') AS title,
  coalesce(u.last_seen, '') AS last_seen
ORDER BY last_seen DESC
LIMIT $limit`

	result, err := session.Run(ctx, query, map[string]any{"limit": limit})
	if err != nil {
		return nil, fmt.Errorf("query urls: %w", err)
	}

	var out []URLView
	for result.Next(ctx) {
		rec := result.Record()
		out = append(out, URLView{
			URL:        fmt.Sprintf("%v", recordValue(rec, "url")),
			Host:       fmt.Sprintf("%v", recordValue(rec, "host")),
			StatusCode: toInt64(recordValue(rec, "status_code")),
			Title:      fmt.Sprintf("%v", recordValue(rec, "title")),
			LastSeen:   fmt.Sprintf("%v", recordValue(rec, "last_seen")),
		})
	}
	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("query urls: %w", err)
	}

	return out, nil
}

func (c *Client) ListServices(ctx context.Context, limit int) ([]ServiceView, error) {
	if limit <= 0 {
		limit = 100
	}

	session := c.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	query := `
MATCH (s:Service)
OPTIONAL MATCH (i:IP)-[:HAS_SERVICE]->(s)
OPTIONAL MATCH (d:Subdomain)-[:RESOLVES_TO]->(i)
WITH s,
     collect(DISTINCT d.fqdn) AS dns_names,
     coalesce(s.ip, '') AS ip,
     toInteger(coalesce(s.port, 0)) AS port,
     coalesce(s.product, '') AS product,
     coalesce(s.tls, false) AS tls,
     coalesce(s.server, '') AS server,
     coalesce(s.banner, '') AS banner,
     coalesce(s.last_seen, '') AS last_seen
RETURN
  ip,
  port,
  product,
  tls,
  server,
  banner,
  last_seen,
  CASE WHEN size(dns_names) > 0 THEN dns_names[0] ELSE '' END AS dns_name,
  size(dns_names) AS dns_count
ORDER BY last_seen DESC
LIMIT $limit`

	result, err := session.Run(ctx, query, map[string]any{"limit": limit})
	if err != nil {
		return nil, fmt.Errorf("query services: %w", err)
	}

	var out []ServiceView
	for result.Next(ctx) {
		rec := result.Record()
		ip := fmt.Sprintf("%v", recordValue(rec, "ip"))
		port := toInt64(recordValue(rec, "port"))
		out = append(out, ServiceView{
			Service:  fmt.Sprintf("%s:%d", ip, port),
			DNSName:  fmt.Sprintf("%v", recordValue(rec, "dns_name")),
			DNSCount: toInt64(recordValue(rec, "dns_count")),
			IP:       ip,
			Port:     port,
			Product:  fmt.Sprintf("%v", recordValue(rec, "product")),
			TLS:      toBool(recordValue(rec, "tls")),
			Server:   fmt.Sprintf("%v", recordValue(rec, "server")),
			Banner:   fmt.Sprintf("%v", recordValue(rec, "banner")),
			LastSeen: fmt.Sprintf("%v", recordValue(rec, "last_seen")),
		})
	}
	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("query services: %w", err)
	}

	return out, nil
}

// EnricherProgress represents how far each enricher has progressed through its
// eligible node pool.
type EnricherProgress struct {
	Enricher string  `json:"enricher"`
	NodeType string  `json:"node_type"`
	Done     int64   `json:"done"`
	Total    int64   `json:"total"`
	Pct      float64 `json:"pct"`
}

// EnricherInfo pairs an enricher name with the node type it subscribes to.
type EnricherInfo struct {
	Name     string
	NodeType string
}

// ListEnricherProgress returns per-enricher completion stats by matching
// each enricher against only the node type it subscribes to.
func (c *Client) ListEnricherProgress(ctx context.Context, enrichers []EnricherInfo) ([]EnricherProgress, error) {
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	// Build a list of {name, node_type} maps for the UNWIND.
	var items []map[string]any
	for _, e := range enrichers {
		items = append(items, map[string]any{"name": e.Name, "node_type": e.NodeType})
	}
	if len(items) == 0 {
		return nil, nil
	}

	// We need separate queries per node type because Cypher doesn't support
	// dynamic labels in MATCH. Group enrichers by node type, run one query
	// per group, then merge.
	byType := make(map[string][]string)
	for _, e := range enrichers {
		byType[e.NodeType] = append(byType[e.NodeType], e.Name)
	}

	var out []EnricherProgress
	for nodeType, names := range byType {
		query := fmt.Sprintf(`
UNWIND $names AS ename
MATCH (n:%s)
WITH ename, count(n) AS total,
     sum(CASE WHEN ename IN coalesce(n.enriched_by, []) THEN 1 ELSE 0 END) AS done
RETURN ename AS enricher, done, total
ORDER BY enricher`, nodeType)

		result, err := session.Run(ctx, query, map[string]any{"names": names})
		if err != nil {
			return nil, fmt.Errorf("query enricher progress for %s: %w", nodeType, err)
		}

		for result.Next(ctx) {
			rec := result.Record()
			done := toInt64(recordValue(rec, "done"))
			total := toInt64(recordValue(rec, "total"))
			pct := float64(0)
			if total > 0 {
				pct = float64(done) / float64(total) * 100
			}
			out = append(out, EnricherProgress{
				Enricher: fmt.Sprintf("%v", recordValue(rec, "enricher")),
				NodeType: nodeType,
				Done:     done,
				Total:    total,
				Pct:      pct,
			})
		}
		if err := result.Err(); err != nil {
			return nil, fmt.Errorf("query enricher progress for %s: %w", nodeType, err)
		}
	}
	return out, nil
}

// RecentActivity represents a recent graph event for the activity feed.
type RecentActivity struct {
	Type      string `json:"type"`
	Label     string `json:"label"`
	Detail    string `json:"detail"`
	Timestamp string `json:"timestamp"`
}

// ListRecentActivity returns the most recent graph events (new nodes, findings, etc).
func (c *Client) ListRecentActivity(ctx context.Context, limit int) ([]RecentActivity, error) {
	if limit <= 0 {
		limit = 30
	}

	session := c.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	query := `
MATCH (n)
WHERE n.last_seen IS NOT NULL AND labels(n)[0] IS NOT NULL
WITH labels(n)[0] AS lbl, n
ORDER BY n.last_seen DESC
LIMIT $limit
RETURN
  lbl AS type,
  CASE lbl
    WHEN 'Finding' THEN coalesce(n.title, n.type, 'finding')
    WHEN 'Subdomain' THEN coalesce(n.fqdn, '')
    WHEN 'IP' THEN coalesce(n.ip, '')
    WHEN 'Service' THEN coalesce(n.ip, '') + ':' + toString(coalesce(n.port, 0))
    WHEN 'URL' THEN coalesce(n.url, '')
    WHEN 'Domain' THEN coalesce(n.fqdn, '')
    ELSE coalesce(n.id, n.fqdn, n.ip, n.url, '')
  END AS label,
  CASE lbl
    WHEN 'Finding' THEN coalesce(n.severity, '') + ' / ' + coalesce(n.tool, '')
    WHEN 'Service' THEN coalesce(n.product, '')
    ELSE ''
  END AS detail,
  coalesce(n.last_seen, '') AS timestamp`

	result, err := session.Run(ctx, query, map[string]any{"limit": limit})
	if err != nil {
		return nil, fmt.Errorf("query recent activity: %w", err)
	}

	var out []RecentActivity
	for result.Next(ctx) {
		rec := result.Record()
		out = append(out, RecentActivity{
			Type:      fmt.Sprintf("%v", recordValue(rec, "type")),
			Label:     fmt.Sprintf("%v", recordValue(rec, "label")),
			Detail:    fmt.Sprintf("%v", recordValue(rec, "detail")),
			Timestamp: fmt.Sprintf("%v", recordValue(rec, "timestamp")),
		})
	}
	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("query recent activity: %w", err)
	}
	return out, nil
}
