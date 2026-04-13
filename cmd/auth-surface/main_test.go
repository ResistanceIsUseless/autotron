package main

import (
	"net/url"
	"testing"
)

func TestDiscoveryCandidates(t *testing.T) {
	u, _ := url.Parse("https://login.example.com/auth")
	cs := discoveryCandidates(u)
	if len(cs) < 2 {
		t.Fatalf("expected multiple discovery candidates, got %d", len(cs))
	}
}

func TestContainsFold(t *testing.T) {
	if !containsFold([]string{"plain", "s256"}, "S256") {
		t.Fatal("expected case-insensitive contains true")
	}
	if containsFold([]string{"plain"}, "S256") {
		t.Fatal("expected false when value not present")
	}
}
