package parsers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

type searchDorkJSONParser struct{}

func init() {
	Register(&searchDorkJSONParser{})
}

func (p *searchDorkJSONParser) Name() string { return "search_dork_json" }

type dorkRecord struct {
	Engine  string `json:"engine"`
	Query   string `json:"query"`
	URL     string `json:"url"`
	Title   string `json:"title"`
	Snippet string `json:"snippet"`
	Class   string `json:"class"`
	Rank    int    `json:"rank"`
}

func (p *searchDorkJSONParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var out Result
	seenURL := make(map[string]bool)

	s := bufio.NewScanner(stdout)
	s.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var rec dorkRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}

		u := strings.TrimSpace(rec.URL)
		if u == "" {
			continue
		}
		parsed, err := url.Parse(u)
		if err != nil || parsed.Hostname() == "" {
			continue
		}

		if !seenURL[u] {
			seenURL[u] = true
			out.Nodes = append(out.Nodes, graph.Node{
				Type:       graph.NodeURL,
				PrimaryKey: u,
				Props: map[string]any{
					"url":              u,
					"host":             strings.ToLower(parsed.Hostname()),
					"title":            rec.Title,
					"discovery_source": "search_dork",
				},
			})

			if trigger.Type == graph.NodeDomain || trigger.Type == graph.NodeSubdomain {
				out.Edges = append(out.Edges, graph.Edge{
					Type:     graph.RelSERVES,
					FromType: trigger.Type,
					FromKey:  trigger.PrimaryKey,
					ToType:   graph.NodeURL,
					ToKey:    u,
				})
			}
		}

		class := strings.TrimSpace(strings.ToLower(rec.Class))
		if class == "" {
			class = "indexed-sensitive-path"
		}
		fid := fmt.Sprintf("dork-%s-%s", class, hashKey(trigger.PrimaryKey+"|"+u+"|"+rec.Query))

		out.Findings = append(out.Findings, graph.Finding{
			ID:         fid,
			Type:       "dork-" + class,
			Title:      fmt.Sprintf("Search-indexed candidate: %s", fallbackString(rec.Title, u)),
			Severity:   classifyDorkSeverity(class),
			Confidence: "tentative",
			Tool:       fallbackString(strings.ToLower(rec.Engine), "dorkintel"),
			Evidence: map[string]any{
				"engine":      rec.Engine,
				"query":       rec.Query,
				"matched_url": u,
				"snippet":     rec.Snippet,
				"rank":        rec.Rank,
				"class":       class,
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

func classifyDorkSeverity(class string) string {
	switch class {
	case "indexed-secret", "indexed-token", "indexed-creds":
		return "high"
	case "indexed-admin-surface", "indexed-exposed-config":
		return "medium"
	default:
		return "low"
	}
}

func fallbackString(v, d string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return d
	}
	return v
}
