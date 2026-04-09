package parsers

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/url"
	"strings"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

// urlListParser handles tools that emit URLs, one per line or as JSON:
// gau, waybackurls, katana, hakrawler, gospider, feroxbuster, ffuf, kiterunner, getJS.
//
// Formats handled:
//   - Plain text: one URL per line (gau, waybackurls, katana, hakrawler)
//   - JSON lines: objects with a "url" field (feroxbuster --json, ffuf -of json)
//   - gospider prefixed lines: "[tag] URL" format — extracts URL portion
//
// All URLs are validated and deduplicated. Only http/https URLs are emitted
// as URL nodes; other schemes are silently dropped.
type urlListParser struct{}

func init() {
	Register(&urlListParser{})
}

func (p *urlListParser) Name() string { return "url_list" }

// urlJSONRecord is a minimal struct for JSON-emitting tools.
type urlJSONRecord struct {
	URL    string `json:"url"`
	Input  string `json:"input"`
	Status int    `json:"status"`
}

func (p *urlListParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var result Result
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 512*1024), 512*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		rawURL := p.extractURL(line)
		if rawURL == "" {
			continue
		}

		// Validate and normalize.
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Host == "" {
			continue
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			continue
		}

		// Normalize: strip fragment, lowercase host.
		parsed.Fragment = ""
		parsed.Host = strings.ToLower(parsed.Host)
		normalized := parsed.String()

		if seen[normalized] {
			continue
		}
		seen[normalized] = true

		result.Nodes = append(result.Nodes, graph.Node{
			Type:       graph.NodeURL,
			PrimaryKey: normalized,
			Props: map[string]any{
				"url":    normalized,
				"scheme": parsed.Scheme,
				"host":   parsed.Hostname(),
				"path":   parsed.Path,
			},
		})

		// SERVES edge from triggering Subdomain/URL.
		switch trigger.Type {
		case graph.NodeSubdomain:
			result.Edges = append(result.Edges, graph.Edge{
				Type:     graph.RelSERVES,
				FromType: graph.NodeSubdomain,
				FromKey:  trigger.PrimaryKey,
				ToType:   graph.NodeURL,
				ToKey:    normalized,
				Props: map[string]any{
					"scheme": parsed.Scheme,
				},
			})
		case graph.NodeURL:
			// Discovery chain: parent URL -> child URL via crawling.
			// We don't create a formal edge here — the URL node's existence
			// and the enriched_by stamp on the trigger provide lineage.
		}
	}

	return result, scanner.Err()
}

// extractURL attempts to extract a URL from a line of output. Handles:
// - Plain URL lines
// - JSON objects with "url" field
// - gospider "[tag] URL" format
func (p *urlListParser) extractURL(line string) string {
	// Try JSON first if it looks like JSON.
	if strings.HasPrefix(line, "{") {
		var rec urlJSONRecord
		if err := json.Unmarshal([]byte(line), &rec); err == nil && rec.URL != "" {
			return rec.URL
		}
	}

	// gospider outputs lines like "[url] [code-200] https://example.com/path"
	// or "[href] https://example.com/path"
	if strings.HasPrefix(line, "[") {
		parts := strings.SplitN(line, " ", 3)
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "http://") || strings.HasPrefix(part, "https://") {
				return part
			}
		}
	}

	// Plain URL.
	if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
		return line
	}

	return ""
}
