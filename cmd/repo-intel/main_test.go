package main

import "testing"

func TestDefaultRepoQueries(t *testing.T) {
	qs := defaultRepoQueries("example.com")
	if len(qs) < 2 {
		t.Fatalf("expected multiple queries, got %d", len(qs))
	}
	if qs[0].Type == "" || qs[0].Query == "" {
		t.Fatalf("expected query/type populated: %#v", qs[0])
	}
}

func TestClassifyRepoSeverity(t *testing.T) {
	if got := classifyRepoSeverity("repo-secret-leak", ".env", "API_TOKEN=abcd"); got != "high" {
		t.Fatalf("expected high, got %s", got)
	}
	if got := classifyRepoSeverity("repo-internal-host-leak", "config.yml", "internal host"); got != "low" {
		t.Fatalf("expected low fallback, got %s", got)
	}
}

func TestLikelySensitivePath(t *testing.T) {
	if !likelySensitivePath("configs/.env.production") {
		t.Fatal("expected sensitive path detection true")
	}
	if likelySensitivePath("assets/logo.png") {
		t.Fatal("expected non-sensitive path detection false")
	}
}

func TestQueryPatternsForType(t *testing.T) {
	secret := queryPatternsForType("example.com", "repo-secret-leak")
	if len(secret) == 0 {
		t.Fatal("expected non-empty secret pattern list")
	}
}
