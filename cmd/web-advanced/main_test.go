package main

import "testing"

func TestNormalizeCheck(t *testing.T) {
	if normalizeCheck("desync") != "desync" {
		t.Fatal("expected desync")
	}
	if normalizeCheck("cache-poison") != "cache-poison" {
		t.Fatal("expected cache-poison")
	}
	if normalizeCheck("waf-diff") != "waf-diff" {
		t.Fatal("expected waf-diff")
	}
	if normalizeCheck("ssrf-gadget") != "ssrf-gadget" {
		t.Fatal("expected ssrf-gadget")
	}
	if normalizeCheck("idor-map") != "idor-map" {
		t.Fatal("expected idor-map")
	}
	if normalizeCheck("csrf-audit") != "csrf-audit" {
		t.Fatal("expected csrf-audit")
	}
	if normalizeCheck("unknown") != "" {
		t.Fatal("expected unsupported check to normalize to empty")
	}
}

func TestStatusDrift(t *testing.T) {
	if !statusDrift(200, 403) {
		t.Fatal("expected class drift")
	}
	if statusDrift(200, 201) {
		t.Fatal("did not expect drift within 2xx")
	}
}

func TestIDORCandidates(t *testing.T) {
	got := idorCandidates("/api/v1/users/123")
	if len(got) == 0 {
		t.Fatal("expected idor candidates for numeric path")
	}
}

func TestLooksStateChangingPath(t *testing.T) {
	if !looksStateChangingPath("https://api.example.com/account/settings") {
		t.Fatal("expected state-changing path heuristic true")
	}
	if looksStateChangingPath("https://api.example.com/public/health") {
		t.Fatal("expected state-changing path heuristic false")
	}
}
