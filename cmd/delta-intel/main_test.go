package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestComputeRecords(t *testing.T) {
	current := summary{RunID: "run-2", Services: 120, Findings: 90, CriticalHigh: 8, InScope: 60}
	previous := summary{RunID: "run-1", Services: 50, Findings: 30, CriticalHigh: 3, InScope: 100}

	recs := computeRecords(current, previous, 1.25)
	if len(recs) == 0 {
		t.Fatal("expected at least one delta record")
	}
}

func TestNormalizeCheck(t *testing.T) {
	if normalizeCheck("new-exposure") != "new-exposure" {
		t.Fatal("expected new-exposure")
	}
	if normalizeCheck("all") != "all" {
		t.Fatal("expected all")
	}
	if normalizeCheck("bad") != "" {
		t.Fatal("expected unsupported value to normalize to empty")
	}
}

func TestLoadCurrentAndPrevious(t *testing.T) {
	dir := t.TempDir()
	writeSummary(t, filepath.Join(dir, "run-old.json"), summary{RunID: "run-old", Services: 10})
	writeSummary(t, filepath.Join(dir, "run-new.json"), summary{RunID: "run-new", Services: 20})

	current, previous, ok, err := loadCurrentAndPrevious(dir, "run-new")
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if !ok {
		t.Fatal("expected comparison availability")
	}
	if current.RunID != "run-new" || previous.RunID != "run-old" {
		t.Fatalf("unexpected runs: current=%s previous=%s", current.RunID, previous.RunID)
	}
}

func writeSummary(t *testing.T, path string, s summary) {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal summary: %v", err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write summary: %v", err)
	}
}
