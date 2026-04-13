package parsers

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

// paramDiscoveryParser handles parameter discovery tools: arjun, linkfinder.
//
// Formats handled:
//   - arjun JSON (-oJ -): {"url": "...", "params": [...], "method": "GET"}
//   - linkfinder plain text: one endpoint/URL per line (parsed for params)
//
// Emits: Endpoint nodes with params, EXPOSES edges from trigger URL.
type paramDiscoveryParser struct{}

func init() {
	Register(&paramDiscoveryParser{})
}

func (p *paramDiscoveryParser) Name() string { return "param_discovery" }

// arjunResult represents arjun's JSON output (one per URL scanned).
type arjunResult struct {
	URL    string       `json:"url"`
	Method string       `json:"method"`
	Params []arjunParam `json:"params"`
}

type arjunParam struct {
	Name string `json:"name"`
	Type string `json:"type"` // "query", "body", "json", etc.
}

func (p *paramDiscoveryParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var result Result
	seenEndpoints := make(map[string]bool)

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 512*1024), 512*1024)

	var jsonAttempted bool
	var lines []string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Try arjun JSON first.
		if strings.HasPrefix(line, "{") || strings.HasPrefix(line, "[") {
			// arjun outputs a single JSON object or array.
			if !jsonAttempted {
				jsonAttempted = true
				// Collect all lines — arjun may output a single multi-line JSON.
				lines = append(lines, line)
				continue
			}
		}
		lines = append(lines, line)
	}

	if err := scanner.Err(); err != nil {
		return result, err
	}

	fullOutput := strings.Join(lines, "\n")

	// Attempt arjun JSON parsing (single object or array of objects).
	if jsonAttempted {
		if parsed := p.parseArjunJSON(fullOutput, trigger, seenEndpoints); len(parsed.Nodes) > 0 || len(parsed.Edges) > 0 {
			return parsed, nil
		}
	}

	// Fallback: linkfinder plain-text output (one endpoint per line).
	p.parseLinkfinderText(lines, trigger, &result, seenEndpoints)
	return result, nil
}

func (p *paramDiscoveryParser) parseArjunJSON(data string, trigger graph.Node, seen map[string]bool) Result {
	var result Result

	// Try single object.
	var single arjunResult
	if err := json.Unmarshal([]byte(data), &single); err == nil && single.URL != "" {
		p.addArjunResult(&result, single, trigger, seen)
		return result
	}

	// Try array of objects.
	var arr []arjunResult
	if err := json.Unmarshal([]byte(data), &arr); err == nil {
		for _, rec := range arr {
			if rec.URL == "" {
				continue
			}
			p.addArjunResult(&result, rec, trigger, seen)
		}
	}

	return result
}

func (p *paramDiscoveryParser) addArjunResult(result *Result, rec arjunResult, trigger graph.Node, seen map[string]bool) {
	method := rec.Method
	if method == "" {
		method = "GET"
	}
	targetURL := rec.URL
	if targetURL == "" {
		targetURL = trigger.PrimaryKey
	}

	// Extract param names and types.
	paramNames := make([]string, 0, len(rec.Params))
	paramTypes := make(map[string]string)
	for _, param := range rec.Params {
		if param.Name == "" {
			continue
		}
		paramNames = append(paramNames, param.Name)
		if param.Type != "" {
			paramTypes[param.Name] = param.Type
		}
	}

	key := endpointID(targetURL, method, "/")
	if seen[key] {
		return
	}
	seen[key] = true

	props := map[string]any{
		"endpoint_id": key,
		"url":         targetURL,
		"method":      method,
		"path":        "/",
		"source":      "arjun",
	}
	if len(paramNames) > 0 {
		props["params"] = paramNames
		props["has_params"] = true
	}
	if len(paramTypes) > 0 {
		props["param_types"] = paramTypes
	}

	result.Nodes = append(result.Nodes, graph.Node{
		Type:       graph.NodeEndpoint,
		PrimaryKey: key,
		Props:      props,
	})

	if trigger.Type == graph.NodeURL {
		result.Edges = append(result.Edges, graph.Edge{
			Type:     graph.RelEXPOSES,
			FromType: graph.NodeURL,
			FromKey:  trigger.PrimaryKey,
			ToType:   graph.NodeEndpoint,
			ToKey:    key,
		})
	}
}

func (p *paramDiscoveryParser) parseLinkfinderText(lines []string, trigger graph.Node, result *Result, seen map[string]bool) {
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// linkfinder outputs relative or absolute paths/URLs.
		path := line
		method := "GET"

		// Normalize path: ensure leading slash for relative paths.
		if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") && !strings.HasPrefix(path, "/") {
			path = "/" + path
		}

		baseURL := trigger.PrimaryKey
		key := endpointID(baseURL, method, path)
		if seen[key] {
			continue
		}
		seen[key] = true

		result.Nodes = append(result.Nodes, graph.Node{
			Type:       graph.NodeEndpoint,
			PrimaryKey: key,
			Props: map[string]any{
				"endpoint_id": key,
				"url":         baseURL,
				"method":      method,
				"path":        path,
				"source":      "linkfinder",
			},
		})

		if trigger.Type == graph.NodeURL {
			result.Edges = append(result.Edges, graph.Edge{
				Type:     graph.RelEXPOSES,
				FromType: graph.NodeURL,
				FromKey:  trigger.PrimaryKey,
				ToType:   graph.NodeEndpoint,
				ToKey:    key,
			})
		}
	}
}
