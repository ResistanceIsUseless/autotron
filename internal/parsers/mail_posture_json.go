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

type mailPostureJSONParser struct{}

func init() {
	Register(&mailPostureJSONParser{})
}

func (p *mailPostureJSONParser) Name() string { return "mail_posture_json" }

type mailRecord struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Details  string `json:"details"`
	Domain   string `json:"domain"`
}

func (p *mailPostureJSONParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var out Result

	s := bufio.NewScanner(stdout)
	s.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var rec mailRecord
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

		target := strings.TrimSpace(rec.Domain)
		if target == "" {
			target = trigger.PrimaryKey
		}

		fid := fmt.Sprintf("mail-%s", hashKey(target+"|"+ftype+"|"+rec.Details))
		out.Findings = append(out.Findings, graph.Finding{
			ID:         fid,
			Type:       ftype,
			Title:      fmt.Sprintf("Mail posture issue: %s", ftype),
			Severity:   sev,
			Confidence: "firm",
			Tool:       "mail-posture",
			Evidence: map[string]any{
				"domain":  target,
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
