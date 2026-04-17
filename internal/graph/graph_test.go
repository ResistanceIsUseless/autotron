package graph

import (
	"strings"
	"testing"
)

func TestBuildPendingNodesQuery_NoPredicate(t *testing.T) {
	query := buildPendingNodesQuery(NodeSubdomain, "", "", nil)

	if !strings.Contains(query, "MATCH (n:Subdomain)") {
		t.Fatalf("expected node label in query, got: %s", query)
	}

	if !strings.Contains(query, "NOT $enricher IN coalesce(n.enriched_by, [])") {
		t.Fatalf("expected enriched_by brake clause, got: %s", query)
	}

	if strings.Contains(query, "()") {
		t.Fatalf("did not expect empty predicate wrapper, got: %s", query)
	}

	if !strings.Contains(query, "RETURN n") {
		t.Fatalf("expected return n projection, got: %s", query)
	}
}

func TestBuildPendingNodesQuery_WrapsPredicate(t *testing.T) {
	predicate := "n.in_scope = true OR n.status = 'resolved'"
	query := buildPendingNodesQuery(NodeSubdomain, predicate, "", nil)

	if !strings.Contains(query, "NOT $enricher IN coalesce(n.enriched_by, [])") {
		t.Fatalf("expected enriched_by brake clause, got: %s", query)
	}

	if !strings.Contains(query, "AND (n.in_scope = true OR n.status = 'resolved')") {
		t.Fatalf("expected parenthesized predicate preserving precedence, got: %s", query)
	}
}

func TestBuildPendingNodesQuery_TrimsWhitespacePredicate(t *testing.T) {
	query := buildPendingNodesQuery(NodeURL, "   \n\t  ", "", nil)

	if strings.Contains(query, "AND (") {
		t.Fatalf("did not expect predicate clause for whitespace-only predicate, got: %s", query)
	}
}

func TestBuildPendingNodesQuery_IncludesMatchAndReturns(t *testing.T) {
	query := buildPendingNodesQuery(
		NodeSubdomain,
		"n.in_scope = true",
		"-[:HAS_SERVICE]->(svc:Service)",
		[]string{"svc.port AS port", "coalesce(svc.ip, '') AS resolved_ip"},
	)

	if !strings.Contains(query, "MATCH (n:Subdomain) -[:HAS_SERVICE]->(svc:Service)") {
		t.Fatalf("expected match pattern in query, got: %s", query)
	}

	if !strings.Contains(query, "RETURN n, coalesce(svc.ip, '') AS resolved_ip, svc.port AS port") {
		t.Fatalf("expected additional return projections, got: %s", query)
	}
}
