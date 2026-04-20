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
	Target         string              `json:"target"`
	Flow           string              `json:"flow"`
	Paths          []webscopeV2Path    `json:"paths"`
	Endpoints      []webscopeV2EP      `json:"endpoints"`
	Findings       []webscopeV2Find    `json:"findings"`
	Secrets        []webscopeV2Secret  `json:"secrets"`
	Technologies   []webscopeV2Tech    `json:"technologies"`
	Forms          []webscopeV2Form    `json:"forms"`
	Parameters     []webscopeV2Param   `json:"parameters"`
	GraphQLSchemas []webscopeV2GraphQL `json:"graphql_schemas"`
	WebSockets     []webscopeV2WS      `json:"websockets"`
	Stats          map[string]any      `json:"stats"`
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
	URL        string         `json:"url"`
	Type       string         `json:"type"`
	Severity   string         `json:"severity"`
	Details    string         `json:"details"`
	Category   string         `json:"category"`
	Title      string         `json:"title"`
	Evidence   string         `json:"evidence"`
	Confidence string         `json:"confidence"`
	References []string       `json:"references"`
	Metadata   map[string]any `json:"metadata"`
}

type webscopeV2Secret struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Context string `json:"context"`
	Source  string `json:"source"`
}

type webscopeV2Tech struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Version  string `json:"version"`
	Source   string `json:"source"`
}

type webscopeV2Form struct {
	Action string            `json:"action"`
	Method string            `json:"method"`
	Inputs []webscopeV2Input `json:"inputs"`
	Source string            `json:"source"`
}

type webscopeV2Input struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type webscopeV2Param struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Source string `json:"source"`
}

type webscopeV2GraphQL struct {
	Endpoint      string   `json:"endpoint"`
	Queries       []string `json:"queries"`
	Mutations     []string `json:"mutations"`
	Subscriptions []string `json:"subscriptions"`
	Source        string   `json:"source"`
}

type webscopeV2WS struct {
	URL         string `json:"url"`
	Protocol    string `json:"protocol"`
	Subprotocol string `json:"subprotocol"`
	Source      string `json:"source"`
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

	// Build a base URL from the trigger/output for constructing keys.
	baseURL := out.Target
	if baseURL == "" && trigger.Props != nil {
		if u, ok := trigger.Props["url"].(string); ok {
			baseURL = u
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

	// Process findings (now with richer fields).
	now := time.Now().UTC()
	for _, f := range out.Findings {
		if f.Type == "" {
			continue
		}
		sev := f.Severity
		if sev == "" {
			sev = "info"
		}
		title := f.Title
		if title == "" {
			title = f.Details
		}
		confidence := f.Confidence
		if confidence == "" {
			confidence = "tentative"
		}
		findID := fmt.Sprintf("webscope-%s-%s", f.Type, trigger.PrimaryKey)
		if f.URL != "" {
			findID = fmt.Sprintf("webscope-%s-%s", f.Type, f.URL)
		}
		evidence := map[string]any{
			"url":     f.URL,
			"details": f.Details,
		}
		if f.Evidence != "" {
			evidence["evidence"] = f.Evidence
		}
		if f.Category != "" {
			evidence["category"] = f.Category
		}
		if len(f.References) > 0 {
			evidence["references"] = f.References
		}
		if len(f.Metadata) > 0 {
			evidence["metadata"] = f.Metadata
		}
		result.Findings = append(result.Findings, graph.Finding{
			ID:         findID,
			Type:       f.Type,
			Title:      title,
			Severity:   sev,
			Confidence: confidence,
			Tool:       "webscope",
			Evidence:   evidence,
			FirstSeen:  now,
			LastSeen:   now,
		})
	}

	// Process secrets → Findings with high severity.
	for _, s := range out.Secrets {
		if s.Type == "" {
			continue
		}
		findID := fmt.Sprintf("webscope-secret-%s-%s", s.Type, trigger.PrimaryKey)
		sev := "high"
		if strings.Contains(strings.ToLower(s.Type), "info") {
			sev = "medium"
		}
		result.Findings = append(result.Findings, graph.Finding{
			ID:         findID,
			Type:       "secret-" + s.Type,
			Title:      fmt.Sprintf("Secret detected: %s", s.Type),
			Severity:   sev,
			Confidence: "firm",
			Tool:       "webscope",
			Evidence: map[string]any{
				"secret_type": s.Type,
				"context":     s.Context,
				"source":      s.Source,
			},
			FirstSeen: now,
			LastSeen:  now,
		})
	}

	// Process technologies → Technology nodes linked to trigger URL.
	for _, t := range out.Technologies {
		if t.Name == "" {
			continue
		}
		key := technologyID(t.Name, t.Version)
		result.Nodes = append(result.Nodes, graph.Node{
			Type:       graph.NodeTechnology,
			PrimaryKey: key,
			Props: map[string]any{
				"technology_id": key,
				"name":          t.Name,
				"category":      t.Category,
				"version":       t.Version,
				"source":        t.Source,
			},
		})
		result.Edges = append(result.Edges, graph.Edge{
			Type:     graph.RelRUNS,
			FromType: graph.NodeURL,
			FromKey:  trigger.PrimaryKey,
			ToType:   graph.NodeTechnology,
			ToKey:    key,
		})
	}

	// Process forms → Form nodes linked to trigger URL.
	for _, f := range out.Forms {
		if f.Action == "" {
			continue
		}
		key := formID(baseURL, f.Action)
		props := map[string]any{
			"form_id": key,
			"action":  f.Action,
			"method":  f.Method,
			"source":  f.Source,
		}
		// Store input names as comma-separated list.
		var inputNames []string
		for _, inp := range f.Inputs {
			inputNames = append(inputNames, inp.Name)
		}
		if len(inputNames) > 0 {
			props["inputs"] = strings.Join(inputNames, ",")
		}
		result.Nodes = append(result.Nodes, graph.Node{
			Type:       graph.NodeForm,
			PrimaryKey: key,
			Props:      props,
		})
		result.Edges = append(result.Edges, graph.Edge{
			Type:     graph.RelCONTAINS,
			FromType: graph.NodeURL,
			FromKey:  trigger.PrimaryKey,
			ToType:   graph.NodeForm,
			ToKey:    key,
		})
	}

	// Process GraphQL schemas → Findings (high-value discovery).
	for _, g := range out.GraphQLSchemas {
		if g.Endpoint == "" {
			continue
		}
		findID := fmt.Sprintf("webscope-graphql-%s", g.Endpoint)
		evidence := map[string]any{
			"endpoint": g.Endpoint,
			"source":   g.Source,
		}
		if len(g.Queries) > 0 {
			evidence["queries"] = g.Queries
		}
		if len(g.Mutations) > 0 {
			evidence["mutations"] = g.Mutations
		}
		if len(g.Subscriptions) > 0 {
			evidence["subscriptions"] = g.Subscriptions
		}
		result.Findings = append(result.Findings, graph.Finding{
			ID:         findID,
			Type:       "graphql-endpoint",
			Title:      fmt.Sprintf("GraphQL endpoint: %s", g.Endpoint),
			Severity:   "high",
			Confidence: "firm",
			Tool:       "webscope",
			Evidence:   evidence,
			FirstSeen:  now,
			LastSeen:   now,
		})
		// Also create an Endpoint node for the GraphQL URL.
		epKey := endpointID(baseURL, "POST", g.Endpoint)
		result.Nodes = append(result.Nodes, graph.Node{
			Type:       graph.NodeEndpoint,
			PrimaryKey: epKey,
			Props: map[string]any{
				"endpoint_id": epKey,
				"url":         baseURL,
				"method":      "POST",
				"path":        g.Endpoint,
				"source":      g.Source,
				"type":        "graphql",
			},
		})
		result.Edges = append(result.Edges, graph.Edge{
			Type:     graph.RelEXPOSES,
			FromType: graph.NodeURL,
			FromKey:  trigger.PrimaryKey,
			ToType:   graph.NodeEndpoint,
			ToKey:    epKey,
		})
	}

	// Process WebSocket endpoints → Findings.
	for _, ws := range out.WebSockets {
		if ws.URL == "" {
			continue
		}
		findID := fmt.Sprintf("webscope-websocket-%s", ws.URL)
		result.Findings = append(result.Findings, graph.Finding{
			ID:         findID,
			Type:       "websocket-endpoint",
			Title:      fmt.Sprintf("WebSocket endpoint: %s", ws.URL),
			Severity:   "medium",
			Confidence: "firm",
			Tool:       "webscope",
			Evidence: map[string]any{
				"url":         ws.URL,
				"protocol":    ws.Protocol,
				"subprotocol": ws.Subprotocol,
				"source":      ws.Source,
			},
			FirstSeen: now,
			LastSeen:  now,
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
