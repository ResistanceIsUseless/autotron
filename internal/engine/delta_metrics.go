package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

type deltaSummary struct {
	RunID        string `json:"run_id"`
	StartedAt    string `json:"started_at"`
	Services     int64  `json:"services"`
	URLs         int64  `json:"urls"`
	Findings     int64  `json:"findings"`
	CriticalHigh int64  `json:"critical_high"`
	InScope      int64  `json:"in_scope_assets"`
}

type runMetrics struct {
	mu sync.Mutex

	nodeSeen      map[string]bool
	findingSeen   map[string]bool
	services      int64
	urls          int64
	findings      int64
	criticalHigh  int64
	inScopeAssets int64
}

func newRunMetrics() *runMetrics {
	return &runMetrics{
		nodeSeen:    make(map[string]bool),
		findingSeen: make(map[string]bool),
	}
}

func (m *runMetrics) AddNode(t graph.NodeType, key string, inScope bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	id := fmt.Sprintf("%s|%s", t, strings.TrimSpace(key))
	if id == "|" || m.nodeSeen[id] {
		return
	}
	m.nodeSeen[id] = true

	switch t {
	case graph.NodeService:
		m.services++
	case graph.NodeURL:
		m.urls++
	}

	if inScope {
		m.inScopeAssets++
	}
}

func (m *runMetrics) AddFinding(id, severity string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	id = strings.TrimSpace(id)
	if id == "" || m.findingSeen[id] {
		return
	}
	m.findingSeen[id] = true
	m.findings++

	sev := strings.ToLower(strings.TrimSpace(severity))
	if sev == "critical" || sev == "high" {
		m.criticalHigh++
	}
}

func (m *runMetrics) Summary(runID string, startedAt time.Time) deltaSummary {
	if m == nil {
		return deltaSummary{RunID: runID, StartedAt: startedAt.UTC().Format(time.RFC3339)}
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	return deltaSummary{
		RunID:        runID,
		StartedAt:    startedAt.UTC().Format(time.RFC3339),
		Services:     m.services,
		URLs:         m.urls,
		Findings:     m.findings,
		CriticalHigh: m.criticalHigh,
		InScope:      m.inScopeAssets,
	}
}

func writeDeltaSummary(outputDir string, s deltaSummary) error {
	base := strings.TrimSpace(outputDir)
	if base == "" {
		base = "./output"
	}

	dir := filepath.Join(base, "delta")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	payload, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, s.RunID+".json")
	return os.WriteFile(path, append(payload, '\n'), 0o644)
}
