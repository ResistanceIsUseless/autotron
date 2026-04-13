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
