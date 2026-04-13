package engine

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

func TestRunMetricsSummaryAndWrite(t *testing.T) {
	m := newRunMetrics()
	m.AddNode(graph.NodeURL, "https://example.com", true)
	m.AddNode(graph.NodeService, "1.2.3.4:443", true)
	m.AddFinding("f-1", "high")
	m.AddFinding("f-2", "low")

	s := m.Summary("run-123", time.Unix(1700000000, 0).UTC())
	if s.URLs != 1 || s.Services != 1 || s.Findings != 2 || s.CriticalHigh != 1 {
		t.Fatalf("unexpected summary: %+v", s)
	}

	output := t.TempDir()
	if err := writeDeltaSummary(output, s); err != nil {
		t.Fatalf("write delta summary failed: %v", err)
	}

	path := filepath.Join(output, "delta", "run-123.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected summary file at %s: %v", path, err)
	}
}
