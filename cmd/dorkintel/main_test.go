package main

import "testing"

func TestDefaultDorks(t *testing.T) {
	qs := defaultDorks("Example.COM")
	if len(qs) < 3 {
		t.Fatalf("expected multiple default queries, got %d", len(qs))
	}
	if qs[0].Class == "" || qs[0].Query == "" {
		t.Fatalf("expected first query/class populated: %#v", qs[0])
	}
}

func TestRunValidationUnsupportedEngine(t *testing.T) {
	err := run(config{engine: "duckduckgo", domain: "example.com", maxResults: 5, timeout: 2})
	if err == nil {
		t.Fatal("expected unsupported engine error")
	}
}

func TestRunValidationMissingDomain(t *testing.T) {
	err := run(config{engine: "google", maxResults: 5, timeout: 2})
	if err == nil {
		t.Fatal("expected domain required error")
	}
}

func TestStripXMLNoise(t *testing.T) {
	raw := "  foo\n\tbar   baz  "
	if got := stripXMLNoise(raw); got != "foo bar baz" {
		t.Fatalf("unexpected cleaned XML text: %q", got)
	}
}
