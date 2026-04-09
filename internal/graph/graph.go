package graph

import (
	"context"
	"fmt"
	"log/slog"
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

	if _, err := session.Run(ctx, cypher, params); err != nil {
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
	node := Node{
		Type:       NodeFinding,
		PrimaryKey: finding.ID,
		Props: map[string]any{
			"type":       finding.Type,
			"title":      finding.Title,
			"severity":   finding.Severity,
			"confidence": finding.Confidence,
			"tool":       finding.Tool,
		},
	}
	if len(finding.CVE) > 0 {
		node.Props["cve"] = finding.CVE
	}
	if len(finding.CWE) > 0 {
		node.Props["cwe"] = finding.CWE
	}
	if len(finding.Evidence) > 0 {
		node.Props["evidence"] = finding.Evidence
	}

	if _, err := c.UpsertNode(ctx, node); err != nil {
		return err
	}

	return c.UpsertEdge(ctx, Edge{
		Type:     RelHAS_FINDING,
		FromType: parentType,
		FromKey:  parentKey,
		ToType:   NodeFinding,
		ToKey:    finding.ID,
	})
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

	if _, err := session.Run(ctx, cypher, map[string]any{
		"key":      nodeKey,
		"enricher": enricherName,
	}); err != nil {
		return fmt.Errorf("mark enriched %s(%s) by %s: %w", nodeType, nodeKey, enricherName, err)
	}
	return nil
}

// QueryPendingNodes returns nodes of the given type that have NOT been
// enriched by the named enricher and match the optional predicate.
// The predicate is a raw Cypher WHERE fragment (validated at config load).
func (c *Client) QueryPendingNodes(ctx context.Context, nodeType NodeType, enricherName string, predicate string) ([]Node, error) {
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	var whereClauses []string
	whereClauses = append(whereClauses,
		fmt.Sprintf("NOT '%s' IN coalesce(n.enriched_by, [])", enricherName),
	)
	if predicate != "" {
		whereClauses = append(whereClauses, predicate)
	}

	cypher := fmt.Sprintf(
		`MATCH (n:%s) WHERE %s RETURN n`,
		nodeType, strings.Join(whereClauses, " AND "),
	)

	result, err := session.Run(ctx, cypher, nil)
	if err != nil {
		return nil, fmt.Errorf("query pending %s for %s: %w", nodeType, enricherName, err)
	}

	var nodes []Node
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
		nodes = append(nodes, node)
	}

	return nodes, nil
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
// scope through CNAME chains: if campuscloud.io CNAMEs to azure.com which
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
