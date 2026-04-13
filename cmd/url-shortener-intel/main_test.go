package main

import "testing"

func TestShortenerQueries(t *testing.T) {
	q := shortenerQueries("Example.com")
	if len(q) == 0 {
		t.Fatal("expected non-empty shortener query list")
	}
}

func TestFallbackEnvPrefersExplicit(t *testing.T) {
	if got := fallbackEnv("value", "SOME_ENV_THAT_IS_UNSET"); got != "value" {
		t.Fatalf("expected explicit value fallback, got %q", got)
	}
}
