package engine

import (
	"testing"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

func TestResolveChildDepth_UsesExistingChildDepth(t *testing.T) {
	parent := graph.Node{Type: graph.NodeDomain, PrimaryKey: "example.com", Props: map[string]any{"discovery_depth": 2}}
	child := graph.Node{Type: graph.NodeSubdomain, PrimaryKey: "a.example.com", Props: map[string]any{"discovery_depth": 7}}

	if got := resolveChildDepth(parent, child); got != 7 {
		t.Fatalf("resolveChildDepth mismatch: got %d want %d", got, 7)
	}
}

func TestResolveChildDepth_IncrementsParentDepth(t *testing.T) {
	parent := graph.Node{Type: graph.NodeDomain, PrimaryKey: "example.com", Props: map[string]any{"discovery_depth": 2}}
	child := graph.Node{Type: graph.NodeSubdomain, PrimaryKey: "a.example.com", Props: map[string]any{}}

	if got := resolveChildDepth(parent, child); got != 3 {
		t.Fatalf("resolveChildDepth mismatch: got %d want %d", got, 3)
	}
}

func TestResolveChildDepth_SameNodeKeepsDepth(t *testing.T) {
	parent := graph.Node{Type: graph.NodeURL, PrimaryKey: "https://example.com", Props: map[string]any{"discovery_depth": 4}}
	child := graph.Node{Type: graph.NodeURL, PrimaryKey: "https://example.com", Props: map[string]any{}}

	if got := resolveChildDepth(parent, child); got != 4 {
		t.Fatalf("resolveChildDepth mismatch: got %d want %d", got, 4)
	}
}

func TestExceedsDiscoveryDepth(t *testing.T) {
	if !exceedsDiscoveryDepth(7, 6) {
		t.Fatal("expected depth 7 to exceed max 6")
	}
	if exceedsDiscoveryDepth(6, 6) {
		t.Fatal("expected depth 6 not to exceed max 6")
	}
	if exceedsDiscoveryDepth(100, 0) {
		t.Fatal("expected max depth 0 to disable enforcement")
	}
}

func TestEdgePropsKey_DeterministicOrder(t *testing.T) {
	a := edgePropsKey(map[string]any{"port": 443, "resolved_ip": "1.1.1.1"})
	b := edgePropsKey(map[string]any{"resolved_ip": "1.1.1.1", "port": 443})

	if a != b {
		t.Fatalf("edgePropsKey should be deterministic: %q != %q", a, b)
	}
}
