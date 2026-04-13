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
