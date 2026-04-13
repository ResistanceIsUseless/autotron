package graph

import "testing"

func TestCorrelateFinding_CVECanonicalization(t *testing.T) {
	f := Finding{
		ID:    "nuclei-123",
		Type:  "cve-cve-2023-9999",
		Title: "Test CVE",
		CVE:   []string{"CVE-2023-9999"},
		Evidence: map[string]any{
			"matched_at": "https://api.example.com/login",
		},
	}

	canonicalType, key := CorrelateFinding(f, NodeURL, "https://api.example.com")
	if canonicalType != "cve" {
		t.Fatalf("expected canonical type cve, got %q", canonicalType)
	}
	if key == "" {
		t.Fatal("expected non-empty canonical key")
	}

	id := canonicalFindingID(key, f.ID)
	if id == "" || id == f.ID {
		t.Fatalf("expected stable correlated id, got %q", id)
	}
}

func TestCorrelateFinding_DifferentToolsSameSignalCollide(t *testing.T) {
	f1 := Finding{
		ID:    "nmap-1",
		Type:  "cve-cve-2023-9999",
		Title: "Detected by nmap",
		Tool:  "nmap",
		CVE:   []string{"CVE-2023-9999"},
		Evidence: map[string]any{
			"host": "https://api.example.com",
		},
	}
	f2 := Finding{
		ID:    "nuclei-2",
		Type:  "cve-cve-2023-9999",
		Title: "Detected by nuclei",
		Tool:  "nuclei",
		CVE:   []string{"CVE-2023-9999"},
		Evidence: map[string]any{
			"host": "https://api.example.com",
		},
	}

	_, k1 := CorrelateFinding(f1, NodeURL, "https://api.example.com")
	_, k2 := CorrelateFinding(f2, NodeURL, "https://api.example.com")
	if k1 == "" || k2 == "" {
		t.Fatal("expected non-empty canonical keys")
	}
	id1 := canonicalFindingID(k1, f1.ID)
	id2 := canonicalFindingID(k2, f2.ID)
	if id1 != id2 {
		t.Fatalf("expected correlated IDs to match for same signal: %q vs %q", id1, id2)
	}
}

func TestCanonicalFindingID_Fallback(t *testing.T) {
	id := canonicalFindingID("", "fallback-id")
	if id != "fallback-id" {
		t.Fatalf("expected fallback id, got %q", id)
	}
}

func TestToStringSliceAndToInt64(t *testing.T) {
	ss := toStringSlice([]any{"nmap", "nuclei"})
	if len(ss) != 2 || ss[0] != "nmap" || ss[1] != "nuclei" {
		t.Fatalf("unexpected string slice conversion: %#v", ss)
	}

	if got := toInt64(int32(7)); got != 7 {
		t.Fatalf("unexpected int conversion: %d", got)
	}
	if got := toInt64(float64(9)); got != 9 {
		t.Fatalf("unexpected float conversion: %d", got)
	}
}
