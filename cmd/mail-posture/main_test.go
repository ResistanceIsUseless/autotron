package main

import (
	"context"
	"testing"
)

func TestNormalizeCheck(t *testing.T) {
	if normalizeCheck("all") != "all" {
		t.Fatal("expected all")
	}
	if normalizeCheck("spf-dkim-dmarc") != "spf-dkim-dmarc" {
		t.Fatal("expected spf-dkim-dmarc")
	}
	if normalizeCheck("bad") != "" {
		t.Fatal("expected unsupported check to normalize empty")
	}
}

func TestHasAnyDKIMNoSelectors(t *testing.T) {
	if hasAnyDKIM(testBackground(), "example.com", nil) {
		t.Fatal("expected false with no selectors")
	}
}

func TestExtractDMARCPolicy(t *testing.T) {
	if got := extractDMARCPolicy("v=DMARC1; p=none; rua=mailto:test@example.com"); got != "none" {
		t.Fatalf("expected none, got %s", got)
	}
	if got := extractDMARCPolicy("v=DMARC1; p=reject"); got != "reject" {
		t.Fatalf("expected reject, got %s", got)
	}
}

func TestFirstTXTWithPrefix(t *testing.T) {
	txt := []string{"foo=bar", "v=spf1 include:_spf.example.com -all"}
	if got := firstTXTWithPrefix(txt, "v=spf1"); got == "" {
		t.Fatal("expected SPF record")
	}
}

func TestShorten(t *testing.T) {
	v := "abcdefghijklmnopqrstuvwxyz"
	if got := shorten(v, 10); len(got) != 10 {
		t.Fatalf("expected len 10, got %d (%s)", len(got), got)
	}
}

func testBackground() context.Context { return context.Background() }
