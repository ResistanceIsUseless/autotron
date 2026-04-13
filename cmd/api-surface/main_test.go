package main

import (
	"net/url"
	"strings"
	"testing"
)

func TestExtractOpenAPIEndpoints(t *testing.T) {
	body := []byte(`{
  "openapi": "3.0.0",
  "paths": {
    "/v1/users": {"get": {}, "post": {}},
    "/v1/admin": {"delete": {}}
  }
}`)

	out := extractOpenAPIEndpoints("https://api.example.com", body, 10)
	if len(out) != 3 {
		t.Fatalf("expected 3 endpoints, got %d", len(out))
	}
}

func TestJoinURL(t *testing.T) {
	u := "https://example.com/base"
	out := joinURL(mustParseURL(t, u), "/openapi.json")
	if !strings.Contains(out, "/base/openapi.json") {
		t.Fatalf("unexpected joined URL: %s", out)
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return u
}
