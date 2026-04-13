package parsers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

type deltaReportJSONParser struct{}

func init() {
	Register(&deltaReportJSONParser{})
}

func (p *deltaReportJSONParser) Name() string { return "delta_report_json" }

type deltaRecord struct {
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

func (p *deltaReportJSONParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var out Result

	s := bufio.NewScanner(stdout)
	s.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var rec deltaRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}

		findingType := strings.ToLower(strings.TrimSpace(rec.Type))
		if findingType == "" {
			continue
		}

		title := strings.TrimSpace(rec.Title)
		if title == "" {
			title = fmt.Sprintf("Delta report finding: %s", findingType)
		}

		severity := normalizeSeverity(rec.Severity, "medium")
		confidence := normalizeConfidence(rec.Confidence, "firm")

		currentRun := strings.TrimSpace(rec.CurrentScanRunID)
		if currentRun == "" {
			currentRun = trigger.PrimaryKey
		}

		fid := fmt.Sprintf("delta-%s", hashKey(currentRun+"|"+rec.PreviousScanRunID+"|"+findingType+"|"+rec.Metric+"|"+rec.Details))
		out.Findings = append(out.Findings, graph.Finding{
			ID:         fid,
			Type:       findingType,
			Title:      title,
			Severity:   severity,
			Confidence: confidence,
			Tool:       "delta-intel",
			Evidence: map[string]any{
				"metric":                rec.Metric,
				"details":               rec.Details,
				"current_count":         rec.CurrentCount,
				"previous_count":        rec.PreviousCount,
				"current_scan_run_id":   currentRun,
				"previous_scan_run_id":  rec.PreviousScanRunID,
				"delta_increase":        rec.CurrentCount - rec.PreviousCount,
				"trigger_scan_run_id":   trigger.PrimaryKey,
				"trigger_scan_run_type": trigger.Type,
			},
			FirstSeen: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
		})
	}

	if err := s.Err(); err != nil {
		return Result{}, err
	}

	return out, nil
}
