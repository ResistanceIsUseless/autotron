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
	IP       string `json:"ip"`
	Port     int64  `json:"port"`
	Product  string `json:"product"`
	TLS      bool   `json:"tls"`
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
RETURN
  coalesce(s.ip, '') AS ip,
  toInteger(coalesce(s.port, 0)) AS port,
  coalesce(s.product, '') AS product,
  coalesce(s.tls, false) AS tls,
  coalesce(s.last_seen, '') AS last_seen
ORDER BY last_seen DESC
LIMIT $limit`

	result, err := session.Run(ctx, query, map[string]any{"limit": limit})
	if err != nil {
		return nil, fmt.Errorf("query services: %w", err)
	}

	var out []ServiceView
	for result.Next(ctx) {
		rec := result.Record()
		out = append(out, ServiceView{
			IP:       fmt.Sprintf("%v", recordValue(rec, "ip")),
			Port:     toInt64(recordValue(rec, "port")),
			Product:  fmt.Sprintf("%v", recordValue(rec, "product")),
			TLS:      toBool(recordValue(rec, "tls")),
			LastSeen: fmt.Sprintf("%v", recordValue(rec, "last_seen")),
		})
	}
	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("query services: %w", err)
	}

	return out, nil
}
