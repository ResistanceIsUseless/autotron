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

type repoLeakJSONParser struct{}

func init() {
	Register(&repoLeakJSONParser{})
}

func (p *repoLeakJSONParser) Name() string { return "repo_leak_json" }

type repoLeakRecord struct {
	Provider string `json:"provider"`
	Repo     string `json:"repo"`
	Path     string `json:"path"`
	URL      string `json:"url"`
	Type     string `json:"type"`
	Match    string `json:"match"`
	Line     int    `json:"line"`
	Severity string `json:"severity"`
}

func (p *repoLeakJSONParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var out Result

	s := bufio.NewScanner(stdout)
	s.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var rec repoLeakRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}

		sev := strings.ToLower(strings.TrimSpace(rec.Severity))
		switch sev {
		case "critical", "high", "medium", "low", "info":
		default:
			sev = "medium"
		}

		leakType := strings.TrimSpace(strings.ToLower(rec.Type))
		if leakType == "" {
			leakType = "repo-secret-leak"
		}

		fid := fmt.Sprintf("repo-%s", hashKey(trigger.PrimaryKey+"|"+rec.Provider+"|"+rec.Repo+"|"+rec.Path+"|"+rec.Match))
		out.Findings = append(out.Findings, graph.Finding{
			ID:         fid,
			Type:       leakType,
			Title:      fmt.Sprintf("Repo leak candidate in %s", fallbackString(rec.Repo, "unknown repo")),
			Severity:   sev,
			Confidence: "firm",
			Tool:       "repo-intel",
			Evidence: map[string]any{
				"provider": rec.Provider,
				"repo":     rec.Repo,
				"path":     rec.Path,
				"url":      rec.URL,
				"match":    rec.Match,
				"line":     rec.Line,
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
