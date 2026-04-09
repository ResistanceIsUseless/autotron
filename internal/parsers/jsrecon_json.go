package parsers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

// jsreconJSONParser handles the custom jsRecon tool's JSON output.
// jsRecon performs static analysis on JavaScript files to extract endpoints,
// subdomain references, and detect drift (content changes between scans).
type jsreconJSONParser struct{}

func init() {
	Register(&jsreconJSONParser{})
}

func (p *jsreconJSONParser) Name() string { return "jsrecon_json" }

// jsreconOutput represents the expected JSON output from jsRecon.
type jsreconOutput struct {
	FileURL   string            `json:"file_url"`
	SHA256    string            `json:"sha256"`
	Endpoints []jsreconEndpoint `json:"endpoints"`
	Domains   []string          `json:"domains"`
	Secrets   []jsreconSecret   `json:"secrets"`
	Drift     *jsreconDrift     `json:"drift"`
}

type jsreconEndpoint struct {
	Path   string `json:"path"`
	Method string `json:"method"`
	Full   string `json:"full_url"`
}

type jsreconSecret struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Context string `json:"context"`
	Line    int    `json:"line"`
}

type jsreconDrift struct {
	PreviousSHA256   string   `json:"previous_sha256"`
	AddedEndpoints   []string `json:"added_endpoints"`
	RemovedEndpoints []string `json:"removed_endpoints"`
	Changed          bool     `json:"changed"`
}

func (p *jsreconJSONParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var output jsreconOutput
	if err := json.NewDecoder(stdout).Decode(&output); err != nil {
		return Result{}, fmt.Errorf("decode jsrecon JSON: %w", err)
	}

	var result Result
	now := time.Now().UTC()
	seenSubs := make(map[string]bool)

	// Endpoints -> Endpoint nodes.
	for _, ep := range output.Endpoints {
		method := ep.Method
		if method == "" {
			method = "GET"
		}
		path := ep.Path
		if path == "" {
			continue
		}

		// Determine the base URL for the endpoint.
		baseURL := ep.Full
		if baseURL == "" {
			baseURL = output.FileURL
		}

		key := fmt.Sprintf("%s|%s|%s", baseURL, method, path)
		result.Nodes = append(result.Nodes, graph.Node{
			Type:       graph.NodeEndpoint,
			PrimaryKey: key,
			Props: map[string]any{
				"url":    baseURL,
				"method": method,
				"path":   path,
				"source": "jsrecon",
			},
		})

		// EXPOSES edge from the JS file's parent URL.
		if trigger.Type == graph.NodeJSFile {
			parentURL, _ := trigger.Props["url"].(string)
			if parentURL != "" {
				result.Edges = append(result.Edges, graph.Edge{
					Type:     graph.RelEXPOSES,
					FromType: graph.NodeURL,
					FromKey:  parentURL,
					ToType:   graph.NodeEndpoint,
					ToKey:    key,
				})
			}
		}
	}

	// Domain references -> Subdomain nodes.
	for _, domain := range output.Domains {
		fqdn := strings.ToLower(strings.TrimSuffix(domain, "."))
		if fqdn == "" || seenSubs[fqdn] {
			continue
		}
		seenSubs[fqdn] = true

		result.Nodes = append(result.Nodes, graph.Node{
			Type:       graph.NodeSubdomain,
			PrimaryKey: fqdn,
			Props: map[string]any{
				"fqdn":   fqdn,
				"status": "discovered",
				"source": "jsrecon",
			},
		})
	}

	// Secrets -> Findings.
	for i, secret := range output.Secrets {
		result.Findings = append(result.Findings, graph.Finding{
			ID:         fmt.Sprintf("jsrecon-secret-%s-%d", output.SHA256[:min(12, len(output.SHA256))], i),
			Type:       fmt.Sprintf("js-secret-%s", secret.Type),
			Title:      fmt.Sprintf("Secret (%s) found in %s", secret.Type, output.FileURL),
			Severity:   "high",
			Confidence: "tentative",
			Tool:       "jsrecon",
			Evidence: map[string]any{
				"secret_type": secret.Type,
				"context":     secret.Context,
				"line":        secret.Line,
				"file_url":    output.FileURL,
			},
			FirstSeen: now, LastSeen: now,
		})
	}

	// Drift detection -> Finding.
	if output.Drift != nil && output.Drift.Changed {
		result.Findings = append(result.Findings, graph.Finding{
			ID:         fmt.Sprintf("jsrecon-drift-%s", output.SHA256[:min(12, len(output.SHA256))]),
			Type:       "js-content-drift",
			Title:      fmt.Sprintf("JS file content changed: %s", output.FileURL),
			Severity:   "low",
			Confidence: "confirmed",
			Tool:       "jsrecon",
			Evidence: map[string]any{
				"previous_sha256":   output.Drift.PreviousSHA256,
				"current_sha256":    output.SHA256,
				"added_endpoints":   output.Drift.AddedEndpoints,
				"removed_endpoints": output.Drift.RemovedEndpoints,
			},
			FirstSeen: now, LastSeen: now,
		})
	}

	return result, nil
}
