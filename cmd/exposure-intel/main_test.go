package main

import (
	"encoding/json"
	"testing"
)

func TestClassifyServiceByPortFallback(t *testing.T) {
	svc := classifyService(shodanBanner{Port: 443})
	if svc != "https" {
		t.Fatalf("expected https, got %s", svc)
	}
}

func TestClassifyRisk(t *testing.T) {
	if got := classifyRisk([]string{"CVE-2024-0001"}, 80, "http"); got != "high" {
		t.Fatalf("expected high for CVE-backed record, got %s", got)
	}
	if got := classifyRisk(nil, 22, "ssh"); got != "medium" {
		t.Fatalf("expected medium for sensitive ssh surface, got %s", got)
	}
	if got := classifyRisk(nil, 8080, "http"); got != "low" {
		t.Fatalf("expected low for non-sensitive surface, got %s", got)
	}
}

func TestMapKeysSorted(t *testing.T) {
	in := map[string]json.RawMessage{
		"CVE-2024-0002": {},
		"CVE-2023-9999": {},
	}
	out := mapKeys(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(out))
	}
	if out[0] != "CVE-2023-9999" || out[1] != "CVE-2024-0002" {
		t.Fatalf("expected sorted keys, got %#v", out)
	}
}
