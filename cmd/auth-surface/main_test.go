package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

func TestContainsOpenRedirectSignal(t *testing.T) {
	if !containsOpenRedirectSignal("https://id.example.com/auth?redirect_uri=https://app.example.com/cb") {
		t.Fatal("expected redirect-like signal true")
	}
	if containsOpenRedirectSignal("https://id.example.com/auth?client_id=abc") {
		t.Fatal("expected no redirect signal")
	}
}

func TestSAMLProbeMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/saml/metadata") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<EntityDescriptor entityID="https://id.example.com"><IDPSSODescriptor WantAssertionsSigned="false"></IDPSSODescriptor></EntityDescriptor>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}

	recs, err := samlProbe(context.Background(), srv.Client(), u)
	if err != nil {
		t.Fatalf("saml probe failed: %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("expected saml metadata records")
	}
}
