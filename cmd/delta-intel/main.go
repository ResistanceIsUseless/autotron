package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type config struct {
	runID          string
	stateDir       string
	check          string
	jsonOutput     bool
	minGrowthRatio float64
}

type summary struct {
	RunID        string `json:"run_id"`
	StartedAt    string `json:"started_at"`
	Services     int64  `json:"services"`
	URLs         int64  `json:"urls"`
	Findings     int64  `json:"findings"`
	CriticalHigh int64  `json:"critical_high"`
	InScope      int64  `json:"in_scope_assets"`
}

type record struct {
	Type              string `json:"type"`
	Title             string `json:"title"`
	Severity          string `json:"severity"`
	Confidence        string `json:"confidence"`
	Details           string `json:"details"`
	Metric            string `json:"metric"`
	CurrentCount      int64  `json:"current_count"`
	PreviousCount     int64  `json:"previous_count"`
	CurrentScanRunID  string `json:"current_scan_run_id"`
	PreviousScanRunID string `json:"previous_scan_run_id"`
}

func main() {
	cfg := parseFlags()
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "delta-intel error:", err)
		os.Exit(1)
	}
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.runID, "run-id", "", "current scan run ID")
	flag.StringVar(&cfg.stateDir, "state-dir", "state/delta", "directory containing per-run summary JSON files")
	flag.StringVar(&cfg.check, "check", "new-exposure", "check to run: new-exposure|new-findings|surface-regression|all")
	flag.BoolVar(&cfg.jsonOutput, "json", false, "emit JSONL output")
	flag.Float64Var(&cfg.minGrowthRatio, "min-growth-ratio", 1.25, "minimum growth ratio to flag new exposure/findings")
	flag.Parse()
	return cfg
}

func run(cfg config) error {
	runID := strings.TrimSpace(cfg.runID)
	if runID == "" {
		return errors.New("--run-id is required")
	}
	if strings.TrimSpace(cfg.stateDir) == "" {
		return errors.New("--state-dir is required")
	}
	if cfg.minGrowthRatio < 1.0 {
		return errors.New("--min-growth-ratio must be >= 1.0")
	}

	check := normalizeCheck(cfg.check)
	if check == "" {
		return fmt.Errorf("unsupported --check %q (supported: new-exposure|new-findings|surface-regression|all)", cfg.check)
	}

	current, previous, ok, err := loadCurrentAndPrevious(cfg.stateDir, runID)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}

	recs := computeRecords(current, previous, cfg.minGrowthRatio)
	for _, rec := range recs {
		if check != "all" && rec.Type != checkToFindingType(check) {
			continue
		}
		if cfg.jsonOutput {
			b, _ := json.Marshal(rec)
			fmt.Println(string(b))
		} else {
			fmt.Printf("%s\t%s\n", rec.Type, rec.Details)
		}
	}

	return nil
}

func normalizeCheck(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "new-exposure", "new-findings", "surface-regression", "all":
		return v
	default:
		return ""
	}
}

func checkToFindingType(check string) string {
	switch check {
	case "new-exposure":
		return "delta-new-exposure"
	case "new-findings":
		return "delta-new-findings"
	case "surface-regression":
		return "delta-surface-regression"
	default:
		return ""
	}
}

func loadCurrentAndPrevious(stateDir, runID string) (summary, summary, bool, error) {
	currentPath := filepath.Join(stateDir, runID+".json")
	current, err := loadSummaryFile(currentPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return summary{}, summary{}, false, nil
		}
		return summary{}, summary{}, false, err
	}
	if strings.TrimSpace(current.RunID) == "" {
		current.RunID = runID
	}

	entries, err := os.ReadDir(stateDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return summary{}, summary{}, false, nil
		}
		return summary{}, summary{}, false, err
	}

	paths := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".json") {
			continue
		}
		if strings.EqualFold(name, runID+".json") {
			continue
		}
		paths = append(paths, filepath.Join(stateDir, name))
	}

	sort.Slice(paths, func(i, j int) bool {
		iInfo, iErr := os.Stat(paths[i])
		jInfo, jErr := os.Stat(paths[j])
		if iErr != nil || jErr != nil {
			return paths[i] > paths[j]
		}
		return iInfo.ModTime().After(jInfo.ModTime())
	})

	for _, p := range paths {
		prev, err := loadSummaryFile(p)
		if err != nil {
			continue
		}
		if strings.TrimSpace(prev.RunID) == "" {
			prev.RunID = strings.TrimSuffix(filepath.Base(p), ".json")
		}
		return current, prev, true, nil
	}

	return summary{}, summary{}, false, nil
}

func loadSummaryFile(path string) (summary, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return summary{}, err
	}
	var s summary
	if err := json.Unmarshal(raw, &s); err != nil {
		return summary{}, err
	}
	return s, nil
}

func computeRecords(current, previous summary, minGrowthRatio float64) []record {
	out := make([]record, 0, 4)

	if grewByRatio(current.Services, previous.Services, minGrowthRatio) {
		out = append(out, record{
			Type:              "delta-new-exposure",
			Title:             "Service exposure increased since previous scan",
			Severity:          ratioSeverity(current.Services, previous.Services),
			Confidence:        "firm",
			Details:           fmt.Sprintf("services grew from %d to %d", previous.Services, current.Services),
			Metric:            "services",
			CurrentCount:      current.Services,
			PreviousCount:     previous.Services,
			CurrentScanRunID:  current.RunID,
			PreviousScanRunID: previous.RunID,
		})
	}

	if grewByRatio(current.Findings, previous.Findings, minGrowthRatio) {
		out = append(out, record{
			Type:              "delta-new-findings",
			Title:             "Findings volume increased since previous scan",
			Severity:          ratioSeverity(current.Findings, previous.Findings),
			Confidence:        "firm",
			Details:           fmt.Sprintf("findings grew from %d to %d", previous.Findings, current.Findings),
			Metric:            "findings",
			CurrentCount:      current.Findings,
			PreviousCount:     previous.Findings,
			CurrentScanRunID:  current.RunID,
			PreviousScanRunID: previous.RunID,
		})
	}

	if grewByRatio(current.CriticalHigh, previous.CriticalHigh, 1.10) {
		out = append(out, record{
			Type:              "delta-surface-regression",
			Title:             "Critical/high findings regressed upward",
			Severity:          "high",
			Confidence:        "firm",
			Details:           fmt.Sprintf("critical/high findings changed from %d to %d", previous.CriticalHigh, current.CriticalHigh),
			Metric:            "critical_high",
			CurrentCount:      current.CriticalHigh,
			PreviousCount:     previous.CriticalHigh,
			CurrentScanRunID:  current.RunID,
			PreviousScanRunID: previous.RunID,
		})
	}

	if previous.InScope > 0 {
		drop := previous.InScope - current.InScope
		if drop > 0 && float64(drop)/float64(previous.InScope) >= 0.25 {
			out = append(out, record{
				Type:              "delta-surface-regression",
				Title:             "In-scope asset coverage dropped",
				Severity:          "medium",
				Confidence:        "tentative",
				Details:           fmt.Sprintf("in-scope assets dropped from %d to %d", previous.InScope, current.InScope),
				Metric:            "in_scope_assets",
				CurrentCount:      current.InScope,
				PreviousCount:     previous.InScope,
				CurrentScanRunID:  current.RunID,
				PreviousScanRunID: previous.RunID,
			})
		}
	}

	return out
}

func grewByRatio(current, previous int64, ratio float64) bool {
	if current <= 0 {
		return false
	}
	if previous <= 0 {
		return current >= 10
	}
	return float64(current)/float64(previous) >= ratio
}

func ratioSeverity(current, previous int64) string {
	if previous <= 0 {
		if current >= 100 {
			return "high"
		}
		if current >= 25 {
			return "medium"
		}
		return "low"
	}
	r := float64(current) / float64(previous)
	if r >= 2.0 {
		return "high"
	}
	if r >= 1.5 {
		return "medium"
	}
	return "low"
}
