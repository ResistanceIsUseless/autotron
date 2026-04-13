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

type visualClusterJSONParser struct{}

func init() {
	Register(&visualClusterJSONParser{})
}

func (p *visualClusterJSONParser) Name() string { return "visual_cluster_json" }

type visualClusterRecord struct {
	URL            string `json:"url"`
	ScreenshotPath string `json:"screenshot_path"`
	ClusterKey     string `json:"cluster_key"`
	Label          string `json:"label"`
	Type           string `json:"type"`
	Severity       string `json:"severity"`
	Confidence     string `json:"confidence"`
	Details        string `json:"details"`
}

func (p *visualClusterJSONParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var out Result

	s := bufio.NewScanner(stdout)
	s.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var rec visualClusterRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}

		targetURL := strings.TrimSpace(rec.URL)
		if targetURL == "" {
			targetURL = trigger.PrimaryKey
		}

		clusterKey := strings.TrimSpace(rec.ClusterKey)
		if clusterKey != "" && trigger.Type == graph.NodeURL {
			out.Nodes = append(out.Nodes, graph.Node{
				Type:       graph.NodeURL,
				PrimaryKey: trigger.PrimaryKey,
				Props: map[string]any{
					"url":                  trigger.PrimaryKey,
					"visual_cluster_key":   clusterKey,
					"visual_cluster_label": strings.TrimSpace(rec.Label),
				},
			})
		}

		fType := strings.ToLower(strings.TrimSpace(rec.Type))
		if fType == "" {
			fType = "visual-cluster-observed"
		}
		severity := normalizeSeverity(rec.Severity, "low")
		confidence := normalizeConfidence(rec.Confidence, "firm")
		details := strings.TrimSpace(rec.Details)
		if details == "" {
			details = fmt.Sprintf("Visual cluster signal: %s", fType)
		}

		fid := fmt.Sprintf("visual-%s", hashKey(targetURL+"|"+clusterKey+"|"+fType+"|"+details))
		out.Findings = append(out.Findings, graph.Finding{
			ID:         fid,
			Type:       fType,
			Title:      details,
			Severity:   severity,
			Confidence: confidence,
			Tool:       "screenshot-cluster",
			Evidence: map[string]any{
				"url":             targetURL,
				"screenshot_path": rec.ScreenshotPath,
				"cluster_key":     clusterKey,
				"label":           rec.Label,
				"details":         rec.Details,
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
