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

type httpAdvancedVulnJSONParser struct{}

func init() {
	Register(&httpAdvancedVulnJSONParser{})
}

func (p *httpAdvancedVulnJSONParser) Name() string { return "http_advanced_vuln_json" }

type httpAdvancedRecord struct {
	URL        string `json:"url"`
	Type       string `json:"type"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Signal     string `json:"signal"`
	Details    string `json:"details"`
}

func (p *httpAdvancedVulnJSONParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var out Result

	s := bufio.NewScanner(stdout)
	s.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var rec httpAdvancedRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}

		ftype := strings.ToLower(strings.TrimSpace(rec.Type))
		if ftype == "" {
			continue
		}
		sev := strings.ToLower(strings.TrimSpace(rec.Severity))
		if sev == "" {
			sev = "high"
		}
		conf := strings.ToLower(strings.TrimSpace(rec.Confidence))
		if conf == "" {
			conf = "firm"
		}
		target := strings.TrimSpace(rec.URL)
		if target == "" {
			target = trigger.PrimaryKey
		}

		fid := fmt.Sprintf("webadv-%s", hashKey(target+"|"+ftype+"|"+rec.Signal+"|"+rec.Details))
		out.Findings = append(out.Findings, graph.Finding{
			ID:         fid,
			Type:       ftype,
			Title:      fmt.Sprintf("Advanced web finding: %s", ftype),
			Severity:   sev,
			Confidence: conf,
			Tool:       "web-advanced",
			Evidence: map[string]any{
				"url":     target,
				"signal":  rec.Signal,
				"details": rec.Details,
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
