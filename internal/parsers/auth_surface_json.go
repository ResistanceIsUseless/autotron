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

type authSurfaceJSONParser struct{}

func init() {
	Register(&authSurfaceJSONParser{})
}

func (p *authSurfaceJSONParser) Name() string { return "auth_surface_json" }

type authRecord struct {
	URL        string `json:"url"`
	Type       string `json:"type"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Details    string `json:"details"`
}

func (p *authSurfaceJSONParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var out Result

	s := bufio.NewScanner(stdout)
	s.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var rec authRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		ftype := strings.ToLower(strings.TrimSpace(rec.Type))
		if ftype == "" {
			continue
		}
		sev := strings.ToLower(strings.TrimSpace(rec.Severity))
		if sev == "" {
			sev = "medium"
		}
		conf := strings.ToLower(strings.TrimSpace(rec.Confidence))
		if conf == "" {
			conf = "firm"
		}

		targetURL := strings.TrimSpace(rec.URL)
		if targetURL == "" {
			targetURL = trigger.PrimaryKey
		}

		fid := fmt.Sprintf("auth-%s", hashKey(targetURL+"|"+ftype+"|"+rec.Details))
		out.Findings = append(out.Findings, graph.Finding{
			ID:         fid,
			Type:       ftype,
			Title:      fmt.Sprintf("Auth surface finding: %s", ftype),
			Severity:   sev,
			Confidence: conf,
			Tool:       "auth-surface",
			Evidence: map[string]any{
				"url":     targetURL,
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
