package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// Client wraps a Neo4j driver and provides graph operations for the ASM
// pipeline. All mutations flow through this client — enrichers never touch
// Neo4j directly.
type Client struct {
	driver neo4j.DriverWithContext
	logger *slog.Logger
}

var asAliasPattern = regexp.MustCompile(`(?i)^(.+)\s+AS\s+([A-Za-z_][A-Za-z0-9_]*)$`)

// NewClient creates a graph client and verifies connectivity.
func NewClient(ctx context.Context, uri, username, password string, logger *slog.Logger) (*Client, error) {
	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(username, password, ""))
	if err != nil {
		return nil, fmt.Errorf("neo4j driver: %w", err)
	}

	if err := driver.VerifyConnectivity(ctx); err != nil {
		driver.Close(ctx)
		return nil, fmt.Errorf("neo4j connectivity: %w", err)
	}

	logger.Info("connected to neo4j", "uri", uri)
	return &Client{driver: driver, logger: logger}, nil
}

// Close shuts down the Neo4j driver.
func (c *Client) Close(ctx context.Context) error {
	return c.driver.Close(ctx)
}

// RunCypher executes an arbitrary Cypher statement. Intended for testing and
// administrative operations only.
func (c *Client) RunCypher(ctx context.Context, cypher string, params map[string]any) error {
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)
	_, err := session.Run(ctx, cypher, params)
	return err
}

// InitSchema creates constraints and indexes. Idempotent — safe to call on
// every startup.
func (c *Client) InitSchema(ctx context.Context) error {
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	stmts := append(Constraints(), Indexes()...)
	for _, stmt := range stmts {
		if _, err := session.Run(ctx, stmt, nil); err != nil {
			return fmt.Errorf("schema init %q: %w", stmt, err)
		}
	}
	c.logger.Info("schema initialized", "constraints", len(Constraints()), "indexes", len(Indexes()))
	return nil
}

// UpsertNode merges a node by its primary key and sets/updates all properties.
// Returns true if the node was newly created (vs updated).
func (c *Client) UpsertNode(ctx context.Context, node Node) (created bool, err error) {
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	pkField := PrimaryKeyField(node.Type)

	// Build property SET clause. We always update last_seen and merge other props.
	props := make(map[string]any)
	for k, v := range node.Props {
		props[k] = v
	}
	props[pkField] = node.PrimaryKey
	props["last_seen"] = time.Now().UTC().Format(time.RFC3339)

	// Use ON CREATE to set first_seen only when new.
	cypher := fmt.Sprintf(
		`MERGE (n:%s {%s: $pk})
		 ON CREATE SET n += $props, n.first_seen = $now
		 ON MATCH SET n += $props
		 RETURN n.first_seen = $now AS created`,
		node.Type, pkField,
	)

	now := time.Now().UTC().Format(time.RFC3339)
	result, err := session.Run(ctx, cypher, map[string]any{
		"pk":    node.PrimaryKey,
		"props": props,
		"now":   now,
	})
	if err != nil {
		return false, fmt.Errorf("upsert %s(%s): %w", node.Type, node.PrimaryKey, err)
	}

	if result.Next(ctx) {
		val, _ := result.Record().Get("created")
		created, _ = val.(bool)
	}
	if err := result.Err(); err != nil {
		return false, fmt.Errorf("upsert %s(%s): %w", node.Type, node.PrimaryKey, err)
	}

	c.logger.Debug("upserted node", "type", node.Type, "key", node.PrimaryKey, "created", created)
	return created, nil
}

// UpsertEdge merges a relationship between two nodes identified by their
// primary keys. Both endpoint nodes must already exist.
func (c *Client) UpsertEdge(ctx context.Context, edge Edge) error {
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	fromPK := PrimaryKeyField(edge.FromType)
	toPK := PrimaryKeyField(edge.ToType)

	// Build optional property SET clause for the relationship.
	var propClause string
	if len(edge.Props) > 0 {
		propClause = " SET r += $props"
	}

	cypher := fmt.Sprintf(
		`MATCH (a:%s {%s: $from_key})
		 MATCH (b:%s {%s: $to_key})
		 MERGE (a)-[r:%s]->(b)%s`,
		edge.FromType, fromPK,
		edge.ToType, toPK,
		edge.Type, propClause,
	)

	params := map[string]any{
		"from_key": edge.FromKey,
		"to_key":   edge.ToKey,
	}
	if len(edge.Props) > 0 {
		params["props"] = edge.Props
	}

	result, err := session.Run(ctx, cypher, params)
	if err != nil {
		return fmt.Errorf("upsert edge %s->%s(%s->%s): %w",
			edge.FromType, edge.ToType, edge.FromKey, edge.ToKey, err)
	}
	if _, err := result.Consume(ctx); err != nil {
		return fmt.Errorf("upsert edge %s->%s(%s->%s): %w",
			edge.FromType, edge.ToType, edge.FromKey, edge.ToKey, err)
	}

	c.logger.Debug("upserted edge",
		"type", edge.Type,
		"from", fmt.Sprintf("%s(%s)", edge.FromType, edge.FromKey),
		"to", fmt.Sprintf("%s(%s)", edge.ToType, edge.ToKey),
	)
	return nil
}

// UpsertFinding persists a Finding node and creates a HAS_FINDING edge from
// the parent node.
func (c *Client) UpsertFinding(ctx context.Context, finding Finding, parentType NodeType, parentKey string) error {
	canonicalType, canonicalKey := CorrelateFinding(finding, parentType, parentKey)
	findingID := canonicalFindingID(canonicalKey, finding.ID)
	parentPK := PrimaryKeyField(parentType)
	now := time.Now().UTC().Format(time.RFC3339)
	evidenceJSON := ""
	if len(finding.Evidence) > 0 {
		if raw, err := json.Marshal(finding.Evidence); err == nil {
			evidenceJSON = string(raw)
		}
	}
	cve := finding.CVE
	if len(cve) == 0 {
		cve = nil
	}
	cwe := finding.CWE
	if len(cwe) == 0 {
		cwe = nil
	}

	session := c.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	cypher := fmt.Sprintf(`
MATCH (p:%s {%s: $parent_key})
MERGE (f:Finding {id: $id})
ON CREATE SET
  f.type = $type,
  f.title = $title,
  f.severity = coalesce($severity, 'info'),
  f.confidence = coalesce($confidence, 'tentative'),
  f.tool = $tool,
  f.tools = [$tool],
  f.source_ids = [$source_id],
  f.canonical_type = $canonical_type,
  f.canonical_key = $canonical_key,
  f.cve = $cve,
  f.cwe = $cwe,
  f.evidence_json = $evidence_json,
  f.first_seen = $now,
  f.last_seen = $now
ON MATCH SET
  f.last_seen = $now,
  f.type = CASE WHEN coalesce(f.type, '') = '' THEN $type ELSE f.type END,
  f.title = CASE WHEN coalesce(f.title, '') = '' THEN $title ELSE f.title END,
  f.severity = CASE
    WHEN (CASE coalesce(f.severity, 'info') WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END)
       >= (CASE coalesce($severity, 'info') WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END)
    THEN f.severity
    ELSE $severity
  END,
  f.confidence = CASE
    WHEN (CASE coalesce(f.confidence, 'tentative') WHEN 'confirmed' THEN 3 WHEN 'firm' THEN 2 ELSE 1 END)
       >= (CASE coalesce($confidence, 'tentative') WHEN 'confirmed' THEN 3 WHEN 'firm' THEN 2 ELSE 1 END)
    THEN f.confidence
    ELSE $confidence
  END,
  f.tool = CASE WHEN coalesce(f.tool, '') = '' THEN $tool ELSE f.tool END,
  f.tools = CASE
    WHEN f.tools IS NULL THEN [$tool]
    WHEN $tool IN f.tools THEN f.tools
    ELSE f.tools + $tool
  END,
  f.source_ids = CASE
    WHEN f.source_ids IS NULL THEN [$source_id]
    WHEN $source_id IN f.source_ids THEN f.source_ids
    ELSE f.source_ids + $source_id
  END,
  f.canonical_type = coalesce(f.canonical_type, $canonical_type),
  f.canonical_key = coalesce(f.canonical_key, $canonical_key),
  f.cve = CASE
    WHEN $cve IS NULL THEN f.cve
    WHEN f.cve IS NULL THEN $cve
    ELSE f.cve + [x IN $cve WHERE NOT x IN f.cve]
  END,
  f.cwe = CASE
    WHEN $cwe IS NULL THEN f.cwe
    WHEN f.cwe IS NULL THEN $cwe
    ELSE f.cwe + [x IN $cwe WHERE NOT x IN f.cwe]
  END,
  f.evidence_json = CASE
    WHEN coalesce(f.evidence_json, '') = '' THEN $evidence_json
    ELSE f.evidence_json
  END
MERGE (p)-[:HAS_FINDING]->(f)
RETURN f.id AS id
`, parentType, parentPK)

	result, err := session.Run(ctx, cypher, map[string]any{
		"parent_key":     parentKey,
		"id":             findingID,
		"source_id":      finding.ID,
		"type":           finding.Type,
		"title":          finding.Title,
		"severity":       finding.Severity,
		"confidence":     finding.Confidence,
		"tool":           finding.Tool,
		"canonical_type": canonicalType,
		"canonical_key":  canonicalKey,
		"cve":            cve,
		"cwe":            cwe,
		"evidence_json":  evidenceJSON,
		"now":            now,
	})
	if err != nil {
		return fmt.Errorf("upsert finding %s: %w", findingID, err)
	}
	if !result.Next(ctx) {
		if err := result.Err(); err != nil {
			return fmt.Errorf("upsert finding %s: %w", findingID, err)
		}
		return fmt.Errorf("upsert finding %s: parent %s(%s) not found", findingID, parentType, parentKey)
	}
	if err := result.Err(); err != nil {
		return fmt.Errorf("upsert finding %s: %w", findingID, err)
	}
	if _, err := result.Consume(ctx); err != nil {
		return fmt.Errorf("upsert finding %s: %w", findingID, err)
	}

	c.logger.Debug("upserted finding",
		"id", findingID,
		"canonical_type", canonicalType,
		"tool", finding.Tool,
		"parent", fmt.Sprintf("%s(%s)", parentType, parentKey),
	)

	return nil
}

// MarkEnriched appends the enricher name to a node's enriched_by list.
// This is the cycle brake — the dispatcher skips nodes already enriched
// by a given enricher.
func (c *Client) MarkEnriched(ctx context.Context, nodeType NodeType, nodeKey string, enricherName string) error {
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	pkField := PrimaryKeyField(nodeType)
	cypher := fmt.Sprintf(
		`MATCH (n:%s {%s: $key})
		 WHERE NOT $enricher IN coalesce(n.enriched_by, [])
		 SET n.enriched_by = coalesce(n.enriched_by, []) + $enricher`,
		nodeType, pkField,
	)

	result, err := session.Run(ctx, cypher, map[string]any{
		"key":      nodeKey,
		"enricher": enricherName,
	})
	if err != nil {
		return fmt.Errorf("mark enriched %s(%s) by %s: %w", nodeType, nodeKey, enricherName, err)
	}
	if _, err := result.Consume(ctx); err != nil {
		return fmt.Errorf("mark enriched %s(%s) by %s: %w", nodeType, nodeKey, enricherName, err)
	}
	return nil
}

// QueryPendingNodes returns nodes of the given type that have NOT been
// enriched by the named enricher and match the optional predicate.
// The predicate is a raw Cypher WHERE fragment (validated at config load).
func (c *Client) QueryPendingNodes(
	ctx context.Context,
	nodeType NodeType,
	enricherName string,
	predicate string,
	match string,
	returns []string,
) ([]PendingWork, error) {
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	cypher := buildPendingNodesQuery(nodeType, predicate, match, returns)

	result, err := session.Run(ctx, cypher, map[string]any{"enricher": enricherName})
	if err != nil {
		return nil, fmt.Errorf("query pending %s for %s: %w", nodeType, enricherName, err)
	}

	var pending []PendingWork
	for result.Next(ctx) {
		record := result.Record()
		val, _ := record.Get("n")
		neo4jNode, ok := val.(neo4j.Node)
		if !ok {
			continue
		}

		node := Node{
			Type:  nodeType,
			Props: make(map[string]any),
		}
		for k, v := range neo4jNode.Props {
			node.Props[k] = v
		}
		// Extract primary key from props.
		pkField := PrimaryKeyField(nodeType)
		if pk, ok := node.Props[pkField]; ok {
			node.PrimaryKey = fmt.Sprintf("%v", pk)
		}
		edgeProps := make(map[string]any)
		for _, field := range returns {
			projection, key, ok := parseReturnProjection(field)
			if !ok {
				continue
			}
			if v, ok := record.Get(key); ok {
				edgeProps[key] = v
			} else if projection != key {
				if v, ok := record.Get(projection); ok {
					edgeProps[key] = v
				}
			}
		}

		pending = append(pending, PendingWork{Node: node, EdgeProps: edgeProps})
	}
	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("query pending %s for %s: %w", nodeType, enricherName, err)
	}

	return pending, nil
}

// ValidatePendingQuery compiles a pending-node subscription query in Neo4j
// using EXPLAIN. This validates syntax for predicate, optional match pattern,
// and additional return projections without executing the query.
func (c *Client) ValidatePendingQuery(
	ctx context.Context,
	nodeType NodeType,
	predicate string,
	match string,
	returns []string,
) error {
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	cypher := buildPendingNodesQuery(nodeType, predicate, match, returns)
	explain := "EXPLAIN " + cypher

	result, err := session.Run(ctx, explain, map[string]any{"enricher": "validate"})
	if err != nil {
		return fmt.Errorf("compile query: %w", err)
	}
	if _, err := result.Consume(ctx); err != nil {
		return fmt.Errorf("compile query: %w", err)
	}

	return nil
}

func parseReturnProjection(field string) (projection string, key string, ok bool) {
	trimmed := strings.TrimSpace(field)
	if trimmed == "" {
		return "", "", false
	}

	matches := asAliasPattern.FindStringSubmatch(trimmed)
	if len(matches) == 3 {
		return strings.TrimSpace(matches[1]), strings.TrimSpace(matches[2]), true
	}

	return trimmed, trimmed, true
}

// TopFindings returns canonical findings prioritized by severity, confidence,
// and number of affected parent assets.
func (c *Client) TopFindings(ctx context.Context, limit int) ([]FindingSummary, error) {
	return c.TopFindingsWithOptions(ctx, TopFindingsOptions{Limit: limit})
}

func (c *Client) TopFindingsWithOptions(ctx context.Context, opts TopFindingsOptions) ([]FindingSummary, error) {
	if opts.Limit <= 0 {
		opts.Limit = 25
	}
	severity := strings.ToLower(strings.TrimSpace(opts.Severity))
	confidence := strings.ToLower(strings.TrimSpace(opts.Confidence))
	tool := strings.ToLower(strings.TrimSpace(opts.Tool))
	since := strings.TrimSpace(opts.Since)

	session := c.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	cypher := `
MATCH (p)-[:HAS_FINDING]->(f:Finding)
WHERE ($severity = '' OR toLower(coalesce(f.severity, '')) = $severity)
  AND ($confidence = '' OR toLower(coalesce(f.confidence, '')) = $confidence)
  AND ($tool = '' OR any(t IN coalesce(f.tools, CASE WHEN f.tool IS NULL THEN [] ELSE [f.tool] END) WHERE toLower(t) = $tool))
  AND ($since = '' OR toString(coalesce(f.last_seen, '')) >= $since)
WITH f, count(DISTINCT p) AS asset_count
OPTIONAL MATCH (p2)-[:HAS_FINDING]->(f)
WITH f, asset_count, collect(DISTINCT p2) AS parents
UNWIND parents AS p2
OPTIONAL MATCH (d:Subdomain)-[:HAS_SERVICE]->(p2)
WITH f, asset_count, p2, collect(DISTINCT d.fqdn) AS service_dns
WITH f, asset_count, collect(DISTINCT
  CASE
    WHEN p2:Service AND size(service_dns) > 0
      THEN service_dns[0] + ' (' + coalesce(p2.fqdn_port, '') + ')'
    ELSE coalesce(
      p2.url,
      p2.fqdn,
      p2.fqdn_port,
      p2.address,
      p2.sha256,
      p2.id,
      ''
    )
  END
) AS assets
RETURN
  f.id AS id,
  f.title AS title,
  f.type AS type,
  coalesce(f.severity, 'info') AS severity,
  coalesce(f.confidence, 'tentative') AS confidence,
  coalesce(f.tools, CASE WHEN f.tool IS NULL THEN [] ELSE [f.tool] END) AS tools,
  asset_count,
  [a IN assets WHERE a <> ''][0..10] AS assets,
  coalesce(f.last_seen, '') AS last_seen,
  coalesce(f.canonical_key, '') AS canonical_key
ORDER BY
  CASE coalesce(f.severity, 'info')
    WHEN 'critical' THEN 5
    WHEN 'high' THEN 4
    WHEN 'medium' THEN 3
    WHEN 'low' THEN 2
    ELSE 1
  END DESC,
  CASE coalesce(f.confidence, 'tentative')
    WHEN 'confirmed' THEN 3
    WHEN 'firm' THEN 2
    ELSE 1
  END DESC,
  asset_count DESC,
  coalesce(f.last_seen, '') DESC
LIMIT $limit`

	result, err := session.Run(ctx, cypher, map[string]any{
		"limit":      opts.Limit,
		"severity":   severity,
		"confidence": confidence,
		"tool":       tool,
		"since":      since,
	})
	if err != nil {
		return nil, fmt.Errorf("query top findings: %w", err)
	}

	var out []FindingSummary
	for result.Next(ctx) {
		rec := result.Record()
		s := FindingSummary{}
		if v, ok := rec.Get("id"); ok {
			s.ID = fmt.Sprintf("%v", v)
		}
		if v, ok := rec.Get("title"); ok {
			s.Title = fmt.Sprintf("%v", v)
		}
		if v, ok := rec.Get("type"); ok {
			s.Type = fmt.Sprintf("%v", v)
		}
		if v, ok := rec.Get("severity"); ok {
			s.Severity = fmt.Sprintf("%v", v)
		}
		if v, ok := rec.Get("confidence"); ok {
			s.Confidence = fmt.Sprintf("%v", v)
		}
		if v, ok := rec.Get("tools"); ok {
			s.Tools = toStringSlice(v)
		}
		if v, ok := rec.Get("asset_count"); ok {
			s.AssetCount = toInt64(v)
		}
		if v, ok := rec.Get("assets"); ok {
			s.Assets = toStringSlice(v)
		}
		if v, ok := rec.Get("last_seen"); ok {
			s.LastSeen = fmt.Sprintf("%v", v)
		}
		if v, ok := rec.Get("canonical_key"); ok {
			s.CanonicalKey = fmt.Sprintf("%v", v)
		}
		out = append(out, s)
	}
	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("query top findings: %w", err)
	}

	return out, nil
}

func toStringSlice(v any) []string {
	switch arr := v.(type) {
	case []string:
		return arr
	case []any:
		out := make([]string, 0, len(arr))
		for _, item := range arr {
			out = append(out, fmt.Sprintf("%v", item))
		}
		return out
	default:
		if strings.TrimSpace(fmt.Sprintf("%v", v)) == "" {
			return nil
		}
		return []string{fmt.Sprintf("%v", v)}
	}
}

func toInt64(v any) int64 {
	switch n := v.(type) {
	case int:
		return int64(n)
	case int64:
		return n
	case int32:
		return int64(n)
	case float64:
		return int64(n)
	case float32:
		return int64(n)
	default:
		return 0
	}
}

func buildPendingNodesQuery(nodeType NodeType, predicate string, match string, returns []string) string {
	whereClauses := []string{"NOT $enricher IN coalesce(n.enriched_by, [])"}

	trimmed := strings.TrimSpace(predicate)
	if trimmed != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("(%s)", trimmed))
	}

	matchClause := strings.TrimSpace(match)
	if matchClause != "" {
		matchClause = " " + matchClause
	}

	returnFields := []string{"n"}
	for _, field := range returns {
		trimmedField := strings.TrimSpace(field)
		if trimmedField == "" {
			continue
		}
		returnFields = append(returnFields, trimmedField)
	}
	sort.Strings(returnFields[1:])

	return fmt.Sprintf(
		`MATCH (n:%s)%s WHERE %s RETURN %s`,
		nodeType, matchClause, strings.Join(whereClauses, " AND "), strings.Join(returnFields, ", "),
	)
}

// SeedDomain creates an in-scope Domain node at discovery depth 0.
// This is the primary entry point for starting a scan.
func (c *Client) SeedDomain(ctx context.Context, fqdn string, scanRunID string) error {
	_, err := c.UpsertNode(ctx, Node{
		Type:       NodeDomain,
		PrimaryKey: fqdn,
		Props: map[string]any{
			"fqdn":            fqdn,
			"in_scope":        true,
			"discovery_depth": 0,
			"scan_run_id":     scanRunID,
			"status":          "seed",
		},
	})
	return err
}

// HasInScopeAncestor checks whether the given subdomain FQDN is reachable
// via a CNAME chain from any in-scope subdomain. This is used to propagate
// scope through CNAME chains: if app.example.com CNAMEs to edge.vendor.net which
// resolves to an IP, that IP should be in-scope even though the azure.com
// intermediary is not.
func (c *Client) HasInScopeAncestor(ctx context.Context, fqdn string) (bool, error) {
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	cypher := `MATCH (s:Subdomain {in_scope: true})-[:CNAME*1..10]->(t:Subdomain {fqdn: $fqdn})
	           RETURN count(s) > 0 AS has_ancestor`

	result, err := session.Run(ctx, cypher, map[string]any{"fqdn": fqdn})
	if err != nil {
		return false, fmt.Errorf("has in-scope ancestor %q: %w", fqdn, err)
	}

	if result.Next(ctx) {
		val, _ := result.Record().Get("has_ancestor")
		if b, ok := val.(bool); ok {
			return b, nil
		}
	}
	return false, nil
}

// AddDomain creates a Domain node for manual enrichment (no scan run required).
func (c *Client) AddDomain(ctx context.Context, fqdn string) error {
	_, err := c.UpsertNode(ctx, Node{
		Type:       NodeDomain,
		PrimaryKey: fqdn,
		Props: map[string]any{
			"fqdn":            fqdn,
			"in_scope":        true,
			"discovery_depth": 0,
			"status":          "manual",
		},
	})
	return err
}

// RemoveDomain removes a Domain node and all its relationships.
func (c *Client) RemoveDomain(ctx context.Context, fqdn string) error {
	return c.RunCypher(ctx, `MATCH (n:Domain {fqdn: $key}) DETACH DELETE n`, map[string]any{"key": fqdn})
}

// AddURL creates a URL node for manual enrichment.
func (c *Client) AddURL(ctx context.Context, rawURL string) error {
	_, err := c.UpsertNode(ctx, Node{
		Type:       NodeURL,
		PrimaryKey: rawURL,
		Props: map[string]any{
			"url":             rawURL,
			"in_scope":        true,
			"discovery_depth": 0,
			"status":          "manual",
		},
	})
	return err
}

// RemoveURL removes a URL node and all its relationships.
func (c *Client) RemoveURL(ctx context.Context, rawURL string) error {
	return c.RunCypher(ctx, `MATCH (n:URL {url: $key}) DETACH DELETE n`, map[string]any{"key": rawURL})
}

// AddJSFile creates a JSFile node for manual enrichment.
func (c *Client) AddJSFile(ctx context.Context, jsfileID string, jsURL string) error {
	_, err := c.UpsertNode(ctx, Node{
		Type:       NodeJSFile,
		PrimaryKey: jsfileID,
		Props: map[string]any{
			"jsfile_id":       jsfileID,
			"url":             jsURL,
			"in_scope":        true,
			"discovery_depth": 0,
			"status":          "manual",
		},
	})
	return err
}

// RemoveJSFile removes a JSFile node and all its relationships.
func (c *Client) RemoveJSFile(ctx context.Context, jsfileID string) error {
	return c.RunCypher(ctx, `MATCH (n:JSFile {jsfile_id: $key}) DETACH DELETE n`, map[string]any{"key": jsfileID})
}
