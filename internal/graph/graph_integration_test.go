package graph

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func TestGraphIntegration_QueryPendingAndMarkEnriched(t *testing.T) {
	ctx := context.Background()
	client := mustIntegrationClient(t, ctx)

	domain := fmt.Sprintf("it-graph-%d.example.com", time.Now().UnixNano())
	t.Cleanup(func() { cleanupTestNodes(t, client, domain) })
	if _, err := client.UpsertNode(ctx, Node{
		Type:       NodeDomain,
		PrimaryKey: domain,
		Props: map[string]any{
			"fqdn":     domain,
			"in_scope": true,
		},
	}); err != nil {
		t.Fatalf("upsert domain: %v", err)
	}

	pending, err := client.QueryPendingNodes(ctx, NodeDomain, "it_enricher", fmt.Sprintf("n.fqdn = '%s'", domain), "", nil)
	if err != nil {
		t.Fatalf("query pending before mark: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending node, got %d", len(pending))
	}

	if err := client.MarkEnriched(ctx, NodeDomain, domain, "it_enricher"); err != nil {
		t.Fatalf("mark enriched: %v", err)
	}

	pending, err = client.QueryPendingNodes(ctx, NodeDomain, "it_enricher", fmt.Sprintf("n.fqdn = '%s'", domain), "", nil)
	if err != nil {
		t.Fatalf("query pending after mark: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected 0 pending nodes after mark, got %d", len(pending))
	}
}

func TestGraphIntegration_QueryPendingWithEdgeContext(t *testing.T) {
	ctx := context.Background()
	client := mustIntegrationClient(t, ctx)

	sub := fmt.Sprintf("it-edge-%d.example.com", time.Now().UnixNano())
	t.Cleanup(func() { cleanupTestNodes(t, client, sub) })
	serviceKey := sub + ":443"

	if _, err := client.UpsertNode(ctx, Node{
		Type:       NodeSubdomain,
		PrimaryKey: sub,
		Props: map[string]any{
			"fqdn":     sub,
			"ips":      "203.0.113.1",
			"in_scope": true,
		},
	}); err != nil {
		t.Fatalf("upsert subdomain: %v", err)
	}
	if _, err := client.UpsertNode(ctx, Node{
		Type:       NodeService,
		PrimaryKey: serviceKey,
		Props: map[string]any{
			"fqdn_port": serviceKey,
			"fqdn":      sub,
			"ip":        "203.0.113.1",
			"port":      443,
			"product":   "https",
			"in_scope":  true,
		},
	}); err != nil {
		t.Fatalf("upsert service: %v", err)
	}

	if err := client.UpsertEdge(ctx, Edge{Type: RelHAS_SERVICE, FromType: NodeSubdomain, FromKey: sub, ToType: NodeService, ToKey: serviceKey}); err != nil {
		t.Fatalf("upsert has_service edge: %v", err)
	}

	pending, err := client.QueryPendingNodes(
		ctx,
		NodeSubdomain,
		"it_httpx",
		fmt.Sprintf("n.fqdn = '%s' AND svc.product = 'https'", sub),
		"-[:HAS_SERVICE]->(svc:Service)",
		[]string{"coalesce(svc.ip, '') AS resolved_ip", "svc.port AS port"},
	)
	if err != nil {
		t.Fatalf("query pending with edge context: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending edge-context node, got %d", len(pending))
	}

	if got := fmt.Sprintf("%v", pending[0].EdgeProps["resolved_ip"]); got != "203.0.113.1" {
		t.Fatalf("unexpected resolved_ip edge prop: %q", got)
	}
	if got := fmt.Sprintf("%v", pending[0].EdgeProps["port"]); got != "443" {
		t.Fatalf("unexpected port edge prop: %q", got)
	}
}

func TestGraphIntegration_ValidatePendingQueryBadPredicate(t *testing.T) {
	ctx := context.Background()
	client := mustIntegrationClient(t, ctx)

	err := client.ValidatePendingQuery(ctx, NodeDomain, "n.in_scope = true AND", "", nil)
	if err == nil {
		t.Fatal("expected bad predicate to fail compile validation")
	}
}

func TestGraphIntegration_UpsertFindingCorrelatesDuplicateSignals(t *testing.T) {
	ctx := context.Background()
	client := mustIntegrationClient(t, ctx)

	url := fmt.Sprintf("https://it-corr-%d.example.com", time.Now().UnixNano())
	t.Cleanup(func() {
		_ = client.RunCypher(ctx, "MATCH (u:URL {url: $url})-[:HAS_FINDING]->(f:Finding) DETACH DELETE f", map[string]any{"url": url})
		_ = client.RunCypher(ctx, "MATCH (u:URL {url: $url}) DETACH DELETE u", map[string]any{"url": url})
	})
	if _, err := client.UpsertNode(ctx, Node{
		Type:       NodeURL,
		PrimaryKey: url,
		Props: map[string]any{
			"url":      url,
			"in_scope": true,
		},
	}); err != nil {
		t.Fatalf("upsert url: %v", err)
	}

	f1 := Finding{
		ID:         "nmap-corr-1",
		Type:       "cve-cve-2023-9999",
		Title:      "Detected by nmap",
		Severity:   "medium",
		Confidence: "firm",
		Tool:       "nmap",
		CVE:        []string{"CVE-2023-9999"},
		Evidence:   map[string]any{"host": url},
	}
	f2 := Finding{
		ID:         "nuclei-corr-2",
		Type:       "cve-cve-2023-9999",
		Title:      "Detected by nuclei",
		Severity:   "high",
		Confidence: "confirmed",
		Tool:       "nuclei",
		CVE:        []string{"CVE-2023-9999"},
		Evidence:   map[string]any{"host": url},
	}

	if err := client.UpsertFinding(ctx, f1, NodeURL, url); err != nil {
		t.Fatalf("upsert first finding: %v", err)
	}
	if err := client.UpsertFinding(ctx, f2, NodeURL, url); err != nil {
		t.Fatalf("upsert second finding: %v", err)
	}

	session := client.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	findingCountResult, err := session.Run(ctx, `MATCH (f:Finding) RETURN count(f) AS c`, nil)
	if err != nil {
		t.Fatalf("query finding count: %v", err)
	}
	if !findingCountResult.Next(ctx) {
		t.Fatal("expected finding count row")
	}
	findingCount, _ := findingCountResult.Record().Get("c")
	if fmt.Sprintf("%v", findingCount) == "0" {
		t.Fatalf("expected finding nodes to exist after upsert, got %v", findingCount)
	}

	countResult, err := session.Run(ctx, `MATCH (:URL {url: $url})-[:HAS_FINDING]->(f:Finding) RETURN count(f) AS c`, map[string]any{"url": url})
	if err != nil {
		t.Fatalf("query canonical finding edge: %v", err)
	}
	if !countResult.Next(ctx) {
		t.Fatal("expected count row")
	}
	countVal, _ := countResult.Record().Get("c")
	if fmt.Sprintf("%v", countVal) != "1" {
		t.Fatalf("expected one canonical HAS_FINDING edge, got %v", countVal)
	}

	propsResult, err := session.Run(ctx, `MATCH (:URL {url: $url})-[:HAS_FINDING]->(f:Finding) RETURN f.id AS id, f.canonical_type AS canonical_type, f.canonical_key AS canonical_key, f.severity AS severity, f.confidence AS confidence`, map[string]any{"url": url})
	if err != nil {
		t.Fatalf("query correlated finding props: %v", err)
	}
	if !propsResult.Next(ctx) {
		t.Fatal("expected finding props row")
	}
	rec := propsResult.Record()
	id, _ := rec.Get("id")
	canonicalType, _ := rec.Get("canonical_type")
	canonicalKey, _ := rec.Get("canonical_key")
	severity, _ := rec.Get("severity")
	confidence, _ := rec.Get("confidence")
	sourceIDsResult, err := session.Run(ctx, `MATCH (:URL {url: $url})-[:HAS_FINDING]->(f:Finding) RETURN f.source_ids AS source_ids, f.tools AS tools`, map[string]any{"url": url})
	if err != nil {
		t.Fatalf("query correlated source metadata: %v", err)
	}
	if !sourceIDsResult.Next(ctx) {
		t.Fatal("expected source metadata row")
	}
	sourceIDs, _ := sourceIDsResult.Record().Get("source_ids")
	tools, _ := sourceIDsResult.Record().Get("tools")
	if !strings.HasPrefix(fmt.Sprintf("%v", id), "corr-") {
		t.Fatalf("expected correlated finding id, got %v", id)
	}
	if fmt.Sprintf("%v", canonicalType) != "cve" || fmt.Sprintf("%v", canonicalKey) == "" {
		t.Fatalf("expected canonical fields populated, got type=%v key=%v", canonicalType, canonicalKey)
	}
	if fmt.Sprintf("%v", severity) != "high" {
		t.Fatalf("expected correlated severity to keep highest signal, got %v", severity)
	}
	if fmt.Sprintf("%v", confidence) != "confirmed" {
		t.Fatalf("expected correlated confidence to keep strongest signal, got %v", confidence)
	}
	if fmt.Sprintf("%v", sourceIDs) == "<nil>" || fmt.Sprintf("%v", tools) == "<nil>" {
		t.Fatalf("expected source/tool rollup arrays, got source_ids=%v tools=%v", sourceIDs, tools)
	}
}

func TestGraphIntegration_TopFindingsReportView(t *testing.T) {
	ctx := context.Background()
	client := mustIntegrationClient(t, ctx)

	url := fmt.Sprintf("https://it-report-%d.example.com", time.Now().UnixNano())
	t.Cleanup(func() {
		_ = client.RunCypher(ctx, "MATCH (u:URL {url: $url})-[:HAS_FINDING]->(f:Finding) DETACH DELETE f", map[string]any{"url": url})
		_ = client.RunCypher(ctx, "MATCH (u:URL {url: $url}) DETACH DELETE u", map[string]any{"url": url})
	})
	if _, err := client.UpsertNode(ctx, Node{
		Type:       NodeURL,
		PrimaryKey: url,
		Props: map[string]any{
			"url":      url,
			"in_scope": true,
		},
	}); err != nil {
		t.Fatalf("upsert url: %v", err)
	}

	if err := client.UpsertFinding(ctx, Finding{
		ID:         "it-report-cve",
		Type:       "cve-cve-2024-0001",
		Title:      "Critical test CVE",
		Severity:   "critical",
		Confidence: "confirmed",
		Tool:       "nuclei",
		CVE:        []string{"CVE-2024-0001"},
		Evidence:   map[string]any{"host": url},
	}, NodeURL, url); err != nil {
		t.Fatalf("upsert finding: %v", err)
	}

	summary, err := client.TopFindings(ctx, 5)
	if err != nil {
		t.Fatalf("top findings query failed: %v", err)
	}
	if len(summary) == 0 {
		t.Fatal("expected top findings rows")
	}
	if summary[0].Severity == "" || summary[0].Confidence == "" {
		t.Fatalf("expected severity/confidence populated in summary: %#v", summary[0])
	}

	filtered, err := client.TopFindingsWithOptions(ctx, TopFindingsOptions{Limit: 5, Severity: "critical", Confidence: "confirmed", Tool: "nuclei"})
	if err != nil {
		t.Fatalf("filtered top findings query failed: %v", err)
	}
	if len(filtered) == 0 {
		t.Fatal("expected filtered top findings rows")
	}
}

func TestGraphIntegration_BuildAndRenderHostReport(t *testing.T) {
	ctx := context.Background()
	client := mustIntegrationClient(t, ctx)

	host := fmt.Sprintf("it-hostreport-%d.example.com", time.Now().UnixNano())
	t.Cleanup(func() { cleanupTestNodes(t, client, host) })
	ip := "198.51.100.77"
	serviceKey := host + ":443"
	reportURL := "https://" + host + "/api/health"

	if _, err := client.UpsertNode(ctx, Node{Type: NodeSubdomain, PrimaryKey: host, Props: map[string]any{"fqdn": host, "ips": ip, "in_scope": true}}); err != nil {
		t.Fatalf("upsert subdomain: %v", err)
	}
	if _, err := client.UpsertNode(ctx, Node{Type: NodeService, PrimaryKey: serviceKey, Props: map[string]any{"fqdn_port": serviceKey, "fqdn": host, "ip": ip, "port": 443, "protocol": "tcp", "product": "https", "tls": true}}); err != nil {
		t.Fatalf("upsert service: %v", err)
	}
	if err := client.UpsertEdge(ctx, Edge{Type: RelHAS_SERVICE, FromType: NodeSubdomain, FromKey: host, ToType: NodeService, ToKey: serviceKey}); err != nil {
		t.Fatalf("upsert has_service: %v", err)
	}
	if _, err := client.UpsertNode(ctx, Node{Type: NodeURL, PrimaryKey: reportURL, Props: map[string]any{"url": reportURL, "status_code": 200, "title": "Health"}}); err != nil {
		t.Fatalf("upsert url: %v", err)
	}
	if err := client.UpsertEdge(ctx, Edge{Type: RelSERVES, FromType: NodeSubdomain, FromKey: host, ToType: NodeURL, ToKey: reportURL}); err != nil {
		t.Fatalf("upsert serves: %v", err)
	}
	if err := client.UpsertFinding(ctx, Finding{
		ID:         "it-host-find-1",
		Type:       "misconfiguration",
		Title:      "Health endpoint exposed",
		Severity:   "medium",
		Confidence: "firm",
		Tool:       "webscope",
		Evidence:   map[string]any{"url": reportURL},
	}, NodeURL, reportURL); err != nil {
		t.Fatalf("upsert finding: %v", err)
	}

	report, err := client.BuildHostReport(ctx, host)
	if err != nil {
		t.Fatalf("build host report: %v", err)
	}
	if report.Host != host {
		t.Fatalf("unexpected host: %s", report.Host)
	}
	if len(report.DNS) == 0 || len(report.OpenPorts) == 0 || len(report.Paths) == 0 || len(report.Findings) == 0 {
		t.Fatalf("expected populated report sections, got dns=%d ports=%d paths=%d findings=%d", len(report.DNS), len(report.OpenPorts), len(report.Paths), len(report.Findings))
	}

	md := RenderHostReportMarkdown(report)
	if !strings.Contains(md, "### "+host) {
		t.Fatalf("markdown missing host heading: %s", md)
	}
	if !strings.Contains(md, "**Discovered URL Paths**") {
		t.Fatalf("markdown missing path section: %s", md)
	}
}

func mustIntegrationClient(t *testing.T, ctx context.Context) *Client {
	t.Helper()

	uri := envOrDefault("NEO4J_URI", "bolt://localhost:7687")
	user := envOrDefault("NEO4J_USERNAME", "neo4j")
	pass := envOrDefault("NEO4J_PASSWORD", "changeme")

	logger := slog.New(slog.NewTextHandler(ioDiscard{}, &slog.HandlerOptions{Level: slog.LevelError}))
	client, err := NewClient(ctx, uri, user, pass, logger)
	if err != nil {
		t.Skipf("neo4j not available for integration tests (%s): %v", uri, err)
	}

	t.Cleanup(func() {
		_ = client.Close(ctx)
	})

	return client
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }

// cleanupTestNodes removes test nodes matching a domain suffix from Neo4j.
// It handles Domain, Subdomain, Service, URL, Finding, and ScanRun nodes.
func cleanupTestNodes(t *testing.T, client *Client, domainSuffix string) {
	t.Helper()
	ctx := context.Background()

	// Delete findings linked to test nodes.
	_ = client.RunCypher(ctx,
		"MATCH (f:Finding) WHERE f.id CONTAINS $suffix DETACH DELETE f",
		map[string]any{"suffix": domainSuffix})

	// Delete URLs matching the suffix.
	_ = client.RunCypher(ctx,
		"MATCH (u:URL) WHERE u.url CONTAINS $suffix DETACH DELETE u",
		map[string]any{"suffix": domainSuffix})

	// Delete services matching the suffix.
	_ = client.RunCypher(ctx,
		"MATCH (s:Service) WHERE s.fqdn ENDS WITH $suffix DETACH DELETE s",
		map[string]any{"suffix": domainSuffix})

	// Delete subdomains matching the suffix.
	_ = client.RunCypher(ctx,
		"MATCH (n:Subdomain) WHERE n.fqdn ENDS WITH $suffix DETACH DELETE n",
		map[string]any{"suffix": domainSuffix})

	// Delete domain nodes.
	_ = client.RunCypher(ctx,
		"MATCH (n:Domain) WHERE n.fqdn ENDS WITH $suffix DETACH DELETE n",
		map[string]any{"suffix": domainSuffix})

	// Delete scan runs.
	_ = client.RunCypher(ctx,
		"MATCH (n:ScanRun) WHERE n.target ENDS WITH $suffix DETACH DELETE n",
		map[string]any{"suffix": domainSuffix})
}
