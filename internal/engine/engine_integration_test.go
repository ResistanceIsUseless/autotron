package engine

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/resistanceisuseless/autotron/internal/config"
	"github.com/resistanceisuseless/autotron/internal/graph"
)

func TestEngineIntegration_SeedDispatchAndConverge(t *testing.T) {
	ctx := context.Background()
	client := mustIntegrationGraphClient(t, ctx)

	domain := fmt.Sprintf("it-engine-%d.example.com", time.Now().UnixNano())
	t.Cleanup(func() { cleanupTestDomain(t, client, domain) })

	cfg := &config.Config{
		Scope: config.ScopeConfig{Domains: []string{"example.com"}},
		Budget: config.BudgetConfig{
			MaxIterations:     4,
			MaxDiscoveryDepth: 6,
			GlobalWorkers:     2,
		},
		Scan: config.ScanConfig{OutputDir: "./output"},
	}

	enrichers := []config.EnricherDef{
		{
			Name:   "it_synthetic",
			Parser: "synthetic_test",
			Subscribes: config.SubscriptionDef{
				NodeType:  graph.NodeDomain,
				Predicate: "n.in_scope = true",
			},
			Command: config.CommandDef{
				Bin:     "/bin/sh",
				Args:    []string{"-c", "printf 'sub1.{{.Node.fqdn}}\n'"},
				Timeout: 5 * time.Second,
			},
			Concurrency: 1,
			Enabled:     true,
		},
	}

	logger := slog.New(slog.NewTextHandler(ioDiscard{}, &slog.HandlerOptions{Level: slog.LevelError}))
	eng := NewEngine(client, cfg, enrichers, logger)

	if err := eng.Run(ctx, []string{domain}); err != nil {
		t.Fatalf("engine run failed: %v", err)
	}

	// The synthetic parser should have emitted one deterministic subdomain.
	sub := "sub1." + domain
	subPending, err := client.QueryPendingNodes(ctx, graph.NodeSubdomain, "it_assert", fmt.Sprintf("n.fqdn = '%s'", sub), "", nil)
	if err != nil {
		t.Fatalf("query subdomain: %v", err)
	}
	if len(subPending) != 1 {
		t.Fatalf("expected subdomain node to exist, got %d matches", len(subPending))
	}

	// Domain should be marked enriched for this enricher, so no pending work remains.
	domainPending, err := client.QueryPendingNodes(ctx, graph.NodeDomain, "it_synthetic", fmt.Sprintf("n.fqdn = '%s'", domain), "", nil)
	if err != nil {
		t.Fatalf("query domain pending: %v", err)
	}
	if len(domainPending) != 0 {
		t.Fatalf("expected no pending domain work after convergence, got %d", len(domainPending))
	}
}

func TestEngineIntegration_TransientRunErrorKeepsNodePending(t *testing.T) {
	ctx := context.Background()
	client := mustIntegrationGraphClient(t, ctx)

	domain := fmt.Sprintf("it-transient-%d.example.com", time.Now().UnixNano())
	t.Cleanup(func() { cleanupTestDomain(t, client, domain) })

	cfg := &config.Config{
		Scope: config.ScopeConfig{Domains: []string{"example.com"}},
		Budget: config.BudgetConfig{
			MaxIterations:     1,
			MaxDiscoveryDepth: 6,
			GlobalWorkers:     1,
		},
	}

	enrichers := []config.EnricherDef{
		{
			Name:   "it_transient_timeout",
			Parser: "synthetic_test",
			Subscribes: config.SubscriptionDef{
				NodeType:  graph.NodeDomain,
				Predicate: "n.in_scope = true",
			},
			Command: config.CommandDef{
				Bin:     "/bin/sh",
				Args:    []string{"-c", "sleep 0.2"},
				Timeout: 25 * time.Millisecond,
				Retries: 1,
			},
			Concurrency: 1,
			Enabled:     true,
		},
	}

	logger := slog.New(slog.NewTextHandler(ioDiscard{}, &slog.HandlerOptions{Level: slog.LevelError}))
	eng := NewEngine(client, cfg, enrichers, logger)
	if err := eng.Run(ctx, []string{domain}); err != nil {
		t.Fatalf("engine run failed: %v", err)
	}

	pending, err := client.QueryPendingNodes(
		ctx,
		graph.NodeDomain,
		"it_transient_timeout",
		fmt.Sprintf("n.fqdn = '%s'", domain),
		"",
		nil,
	)
	if err != nil {
		t.Fatalf("query pending domain: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected transient failure to keep node pending, got %d", len(pending))
	}
}

func TestEngineIntegration_FatalRunErrorMarksNodeEnriched(t *testing.T) {
	ctx := context.Background()
	client := mustIntegrationGraphClient(t, ctx)

	domain := fmt.Sprintf("it-fatal-%d.example.com", time.Now().UnixNano())
	t.Cleanup(func() { cleanupTestDomain(t, client, domain) })

	cfg := &config.Config{
		Scope: config.ScopeConfig{Domains: []string{"example.com"}},
		Budget: config.BudgetConfig{
			MaxIterations:     1,
			MaxDiscoveryDepth: 6,
			GlobalWorkers:     1,
		},
	}

	enrichers := []config.EnricherDef{
		{
			Name:   "it_fatal_exec",
			Parser: "synthetic_test",
			Subscribes: config.SubscriptionDef{
				NodeType:  graph.NodeDomain,
				Predicate: "n.in_scope = true",
			},
			Command: config.CommandDef{
				Bin:     "it-missing-binary-xyz",
				Args:    []string{"-v"},
				Timeout: 1 * time.Second,
			},
			Concurrency: 1,
			Enabled:     true,
		},
	}

	logger := slog.New(slog.NewTextHandler(ioDiscard{}, &slog.HandlerOptions{Level: slog.LevelError}))
	eng := NewEngine(client, cfg, enrichers, logger)
	if err := eng.Run(ctx, []string{domain}); err != nil {
		t.Fatalf("engine run failed: %v", err)
	}

	pending, err := client.QueryPendingNodes(
		ctx,
		graph.NodeDomain,
		"it_fatal_exec",
		fmt.Sprintf("n.fqdn = '%s'", domain),
		"",
		nil,
	)
	if err != nil {
		t.Fatalf("query pending domain: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected fatal exec error to mark node enriched, got %d pending", len(pending))
	}
}

func mustIntegrationGraphClient(t *testing.T, ctx context.Context) *graph.Client {
	t.Helper()

	uri := envOrDefault("NEO4J_URI", "bolt://localhost:7687")
	user := envOrDefault("NEO4J_USERNAME", "neo4j")
	pass := envOrDefault("NEO4J_PASSWORD", "changeme")

	logger := slog.New(slog.NewTextHandler(ioDiscard{}, &slog.HandlerOptions{Level: slog.LevelError}))
	client, err := graph.NewClient(ctx, uri, user, pass, logger)
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

// cleanupTestDomain removes all nodes and relationships created by an
// integration test. It deletes:
//   - Service nodes whose fqdn ends with the domain
//   - URL nodes whose url contains the domain
//   - Finding nodes linked to any of the above
//   - Subdomain nodes ending with the domain
//   - The Domain node with the given fqdn
//   - ScanRun nodes whose target matches the domain
func cleanupTestDomain(t *testing.T, client *graph.Client, domain string) {
	t.Helper()
	ctx := context.Background()

	// Delete findings linked to services of this domain.
	if err := client.RunCypher(ctx,
		"MATCH (s:Service)-[:HAS_FINDING]->(f:Finding) WHERE s.fqdn ENDS WITH $domain DETACH DELETE f",
		map[string]any{"domain": domain},
	); err != nil {
		t.Logf("cleanup service findings: %v", err)
	}

	// Delete findings linked to URLs of this domain.
	if err := client.RunCypher(ctx,
		"MATCH (u:URL)-[:HAS_FINDING]->(f:Finding) WHERE u.url CONTAINS $domain DETACH DELETE f",
		map[string]any{"domain": domain},
	); err != nil {
		t.Logf("cleanup url findings: %v", err)
	}

	// Delete findings linked to the domain or its subdomains.
	if err := client.RunCypher(ctx,
		"MATCH (n:Domain {fqdn: $domain})-[*]-(f:Finding) DETACH DELETE f",
		map[string]any{"domain": domain},
	); err != nil {
		t.Logf("cleanup findings: %v", err)
	}

	// Delete URL nodes.
	if err := client.RunCypher(ctx,
		"MATCH (u:URL) WHERE u.url CONTAINS $domain DETACH DELETE u",
		map[string]any{"domain": domain},
	); err != nil {
		t.Logf("cleanup url nodes: %v", err)
	}

	// Delete Service nodes.
	if err := client.RunCypher(ctx,
		"MATCH (s:Service) WHERE s.fqdn ENDS WITH $domain DETACH DELETE s",
		map[string]any{"domain": domain},
	); err != nil {
		t.Logf("cleanup service nodes: %v", err)
	}

	// Delete subdomains and their relationships.
	if err := client.RunCypher(ctx,
		"MATCH (n:Subdomain) WHERE n.fqdn ENDS WITH $domain DETACH DELETE n",
		map[string]any{"domain": domain},
	); err != nil {
		t.Logf("cleanup subdomain nodes: %v", err)
	}

	// Delete the domain node itself.
	if err := client.RunCypher(ctx,
		"MATCH (n:Domain {fqdn: $domain}) DETACH DELETE n",
		map[string]any{"domain": domain},
	); err != nil {
		t.Logf("cleanup domain node: %v", err)
	}

	// Delete ScanRun nodes created by this test.
	if err := client.RunCypher(ctx,
		"MATCH (n:ScanRun) WHERE n.target = $domain DETACH DELETE n",
		map[string]any{"domain": domain},
	); err != nil {
		t.Logf("cleanup scan run nodes: %v", err)
	}
}
