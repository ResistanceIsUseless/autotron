package main

import (
	"strings"
	"testing"
)

func TestEnableEnrichersInYAML(t *testing.T) {
	raw := `enrichers:
  - name: a_one
    enabled: false
  - name: b_two
    enabled: false
  - name: c_three
    enabled: true
`

	updated, changed, err := enableEnrichersInYAML(raw, []string{"a_one", "c_three", "missing"})
	if err != nil {
		t.Fatalf("enableEnrichersInYAML failed: %v", err)
	}
	if changed != 1 {
		t.Fatalf("expected 1 change, got %d", changed)
	}
	if !strings.Contains(updated, "name: a_one\n    enabled: true") {
		t.Fatal("expected a_one to be enabled")
	}
	if !strings.Contains(updated, "name: b_two\n    enabled: false") {
		t.Fatal("expected b_two to remain disabled")
	}
}
