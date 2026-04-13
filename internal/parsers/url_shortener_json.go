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

type urlShortenerJSONParser struct{}

func init() {
	Register(&urlShortenerJSONParser{})
}

func (p *urlShortenerJSONParser) Name() string { return "url_shortener_json" }

type shortenerRecord struct {
	Engine      string `json:"engine"`
	Query       string `json:"query"`
	ShortURL    string `json:"short_url"`
	FinalURL    string `json:"final_url"`
	Host        string `json:"host"`
	Class       string `json:"class"`
	Rank        int    `json:"rank"`
	ChainLength int    `json:"chain_length"`
}

func (p *urlShortenerJSONParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var out Result
	seen := make(map[string]bool)

	s := bufio.NewScanner(stdout)
	s.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var rec shortenerRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}

		finalURL := strings.TrimSpace(rec.FinalURL)
		if finalURL == "" {
			continue
		}
		u, err := url.Parse(finalURL)
		if err != nil || u.Hostname() == "" {
			continue
		}
		if !seen[finalURL] {
			seen[finalURL] = true
			out.Nodes = append(out.Nodes, graph.Node{
				Type:       graph.NodeURL,
				PrimaryKey: finalURL,
				Props: map[string]any{
					"url":              finalURL,
					"host":             strings.ToLower(strings.TrimSpace(u.Hostname())),
					"discovery_source": "url_shortener",
				},
			})

			if trigger.Type == graph.NodeDomain || trigger.Type == graph.NodeSubdomain {
				out.Edges = append(out.Edges, graph.Edge{
					Type:     graph.RelSERVES,
					FromType: trigger.Type,
					FromKey:  trigger.PrimaryKey,
					ToType:   graph.NodeURL,
					ToKey:    finalURL,
				})
			}
		}

		fType := strings.ToLower(strings.TrimSpace(rec.Class))
		if fType == "" {
			fType = "shortener-resolved-asset"
		}
		fid := fmt.Sprintf("shortener-%s", hashKey(trigger.PrimaryKey+"|"+rec.ShortURL+"|"+finalURL+"|"+rec.Query))
		out.Findings = append(out.Findings, graph.Finding{
			ID:         fid,
			Type:       fType,
			Title:      "Shortened URL resolved to candidate asset",
			Severity:   "low",
			Confidence: "tentative",
			Tool:       "url-shortener-intel",
			Evidence: map[string]any{
				"engine":       rec.Engine,
				"query":        rec.Query,
				"short_url":    rec.ShortURL,
				"final_url":    finalURL,
				"chain_length": rec.ChainLength,
				"rank":         rec.Rank,
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
