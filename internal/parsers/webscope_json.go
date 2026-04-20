package parsers

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

// webscopeJSONParser handles webscope v2 JSON output.
// v2 emits a single JSON object with top-level keys:
//
//	paths[]     – discovered URLs (status, method, content_type, source)
//	endpoints[] – discovered endpoints (path, type, method, source)
//	findings[]  – interesting findings (url, type, severity, details)
//	stats{}     – request statistics
type webscopeJSONParser struct{}

func init() {
	Register(&webscopeJSONParser{})
}

func (p *webscopeJSONParser) Name() string { return "webscope_json" }

// webscopeV2Output matches the top-level JSON structure from webscope v2.
type webscopeV2Output struct {
	Target    string           `json:"target"`
	Flow      string           `json:"flow"`
	Paths     []webscopeV2Path `json:"paths"`
	Endpoints []webscopeV2EP   `json:"endpoints"`
	Findings  []webscopeV2Find `json:"findings"`
	Stats     map[string]any   `json:"stats"`
}

type webscopeV2Path struct {
	URL         string `json:"url"`
	Status      int    `json:"status"`
	Method      string `json:"method"`
	ContentType string `json:"content_type"`
	Source      string `json:"source"`
}

type webscopeV2EP struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Method string `json:"method"`
	Source string `json:"source"`
}

type webscopeV2Find struct {
	URL      string `json:"url"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Details  string `json:"details"`
}

func (p *webscopeJSONParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var out webscopeV2Output
	if err := json.NewDecoder(stdout).Decode(&out); err != nil {
		// Empty or invalid output — treat as no data.
		return Result{}, nil
	}

	var result Result
	seenURLs := make(map[string]bool)
	seenJS := make(map[string]bool)

	// Process paths → URL nodes (and JSFile nodes for .js URLs).
	for _, p := range out.Paths {
		if p.URL == "" || seenURLs[p.URL] {
			continue
		}
		seenURLs[p.URL] = true

		result.Nodes = append(result.Nodes, graph.Node{
			Type:       graph.NodeURL,
			PrimaryKey: p.URL,
			Props: map[string]any{
				"url":          p.URL,
				"status_code":  p.Status,
				"content_type": p.ContentType,
				"method":       p.Method,
				"source":       p.Source,
			},
		})

		// If this looks like a JS file, also create a JSFile node.
		if isJSURL(p.URL) {
			key := jsFileIDFromURL(p.URL)
			if !seenJS[key] {
				seenJS[key] = true
				result.Nodes = append(result.Nodes, graph.Node{
					Type:       graph.NodeJSFile,
					PrimaryKey: key,
					Props: map[string]any{
						"jsfile_id": key,
						"url":       p.URL,
						"sha256":    "unknown",
					},
				})
				if trigger.Type == graph.NodeURL {
					result.Edges = append(result.Edges, graph.Edge{
						Type:     graph.RelLOADS,
						FromType: graph.NodeURL,
						FromKey:  trigger.PrimaryKey,
						ToType:   graph.NodeJSFile,
						ToKey:    key,
					})
				}
			}
		}
	}

	// Process endpoints → Endpoint nodes.
	for _, ep := range out.Endpoints {
		if ep.Path == "" {
			continue
		}
		method := ep.Method
		if method == "" {
			method = "GET"
		}
		// Build a base URL from the trigger to construct the endpoint key.
		baseURL := out.Target
		if baseURL == "" && trigger.Props != nil {
			if u, ok := trigger.Props["url"].(string); ok {
				baseURL = u
			}
		}
		key := endpointID(baseURL, method, ep.Path)
		result.Nodes = append(result.Nodes, graph.Node{
			Type:       graph.NodeEndpoint,
			PrimaryKey: key,
			Props: map[string]any{
				"endpoint_id": key,
				"url":         baseURL,
				"method":      method,
				"path":        ep.Path,
				"source":      ep.Source,
			},
		})
		result.Edges = append(result.Edges, graph.Edge{
			Type:     graph.RelEXPOSES,
			FromType: graph.NodeURL,
			FromKey:  trigger.PrimaryKey,
			ToType:   graph.NodeEndpoint,
			ToKey:    key,
		})
	}

	// Process findings.
	for _, f := range out.Findings {
		if f.Type == "" {
			continue
		}
		sev := f.Severity
		if sev == "" {
			sev = "info"
		}
		findID := fmt.Sprintf("webscope-%s-%s", f.Type, trigger.PrimaryKey)
		if f.URL != "" {
			findID = fmt.Sprintf("webscope-%s-%s", f.Type, f.URL)
		}
		result.Findings = append(result.Findings, graph.Finding{
			ID:         findID,
			Type:       f.Type,
			Title:      f.Details,
			Severity:   sev,
			Confidence: "tentative",
			Tool:       "webscope",
			Evidence: map[string]any{
				"url":     f.URL,
				"details": f.Details,
			},
			FirstSeen: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
		})
	}

	return result, nil
}

// isJSURL returns true if the URL looks like a JavaScript file.
func isJSURL(u string) bool {
	lower := strings.ToLower(u)
	// Strip query string / fragment for extension check.
	if idx := strings.IndexAny(lower, "?#"); idx >= 0 {
		lower = lower[:idx]
	}
	return strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".mjs")
}

// jsFileIDFromURL creates a stable JSFile key from a URL (no sha256 available in v2).
func jsFileIDFromURL(u string) string {
	h := sha256.Sum256([]byte(u))
	return fmt.Sprintf("%x", h[:8])
}
