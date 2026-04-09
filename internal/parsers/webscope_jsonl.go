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

// webscopeJSONLParser handles the custom webscope tool's streaming JSONL output.
// webscope is a comprehensive web crawler that emits URLs, Endpoints, Forms,
// JSFiles, and Findings in a single streaming pass.
type webscopeJSONLParser struct{}

func init() {
	Register(&webscopeJSONLParser{})
}

func (p *webscopeJSONLParser) Name() string { return "webscope_jsonl" }

// webscopeRecord is a polymorphic JSONL record from webscope.
// The "type" field determines which fields are populated.
type webscopeRecord struct {
	Type string `json:"type"` // "url", "endpoint", "form", "jsfile", "finding"

	// URL fields
	URL           string `json:"url,omitempty"`
	StatusCode    int    `json:"status_code,omitempty"`
	ContentType   string `json:"content_type,omitempty"`
	ContentLength int    `json:"content_length,omitempty"`
	Title         string `json:"title,omitempty"`

	// Endpoint fields
	Method string   `json:"method,omitempty"`
	Path   string   `json:"path,omitempty"`
	Params []string `json:"params,omitempty"`

	// Form fields
	Action string   `json:"action,omitempty"`
	Fields []string `json:"fields,omitempty"`

	// JSFile fields
	SHA256 string `json:"sha256,omitempty"`
	Size   int    `json:"size,omitempty"`

	// Finding fields
	FindingType  string         `json:"finding_type,omitempty"`
	FindingTitle string         `json:"finding_title,omitempty"`
	Severity     string         `json:"severity,omitempty"`
	Evidence     map[string]any `json:"evidence,omitempty"`
}

func (p *webscopeJSONLParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var result Result
	seenURLs := make(map[string]bool)
	seenJS := make(map[string]bool)

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var rec webscopeRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}

		switch rec.Type {
		case "url":
			p.processURL(&result, rec, trigger, seenURLs)
		case "endpoint":
			p.processEndpoint(&result, rec, trigger)
		case "form":
			p.processForm(&result, rec, trigger)
		case "jsfile":
			p.processJSFile(&result, rec, trigger, seenJS)
		case "finding":
			p.processFinding(&result, rec, trigger)
		}
	}

	return result, scanner.Err()
}

func (p *webscopeJSONLParser) processURL(result *Result, rec webscopeRecord, trigger graph.Node, seen map[string]bool) {
	if rec.URL == "" || seen[rec.URL] {
		return
	}
	seen[rec.URL] = true

	result.Nodes = append(result.Nodes, graph.Node{
		Type:       graph.NodeURL,
		PrimaryKey: rec.URL,
		Props: map[string]any{
			"url":            rec.URL,
			"status_code":    rec.StatusCode,
			"content_type":   rec.ContentType,
			"content_length": rec.ContentLength,
			"title":          rec.Title,
		},
	})
}

func (p *webscopeJSONLParser) processEndpoint(result *Result, rec webscopeRecord, trigger graph.Node) {
	if rec.URL == "" || rec.Path == "" {
		return
	}

	method := rec.Method
	if method == "" {
		method = "GET"
	}

	key := fmt.Sprintf("%s|%s|%s", rec.URL, method, rec.Path)
	result.Nodes = append(result.Nodes, graph.Node{
		Type:       graph.NodeEndpoint,
		PrimaryKey: key,
		Props: map[string]any{
			"url":    rec.URL,
			"method": method,
			"path":   rec.Path,
			"params": rec.Params,
		},
	})

	result.Edges = append(result.Edges, graph.Edge{
		Type:     graph.RelEXPOSES,
		FromType: graph.NodeURL,
		FromKey:  rec.URL,
		ToType:   graph.NodeEndpoint,
		ToKey:    key,
	})
}

func (p *webscopeJSONLParser) processForm(result *Result, rec webscopeRecord, trigger graph.Node) {
	if rec.URL == "" || rec.Action == "" {
		return
	}

	key := fmt.Sprintf("%s|%s", rec.URL, rec.Action)
	result.Nodes = append(result.Nodes, graph.Node{
		Type:       graph.NodeForm,
		PrimaryKey: key,
		Props: map[string]any{
			"url":    rec.URL,
			"action": rec.Action,
			"fields": rec.Fields,
		},
	})

	result.Edges = append(result.Edges, graph.Edge{
		Type:     graph.RelCONTAINS,
		FromType: graph.NodeURL,
		FromKey:  rec.URL,
		ToType:   graph.NodeForm,
		ToKey:    key,
	})

	// Mark the parent URL as having forms for downstream enrichers.
	result.Nodes = append(result.Nodes, graph.Node{
		Type:       graph.NodeURL,
		PrimaryKey: rec.URL,
		Props: map[string]any{
			"url":       rec.URL,
			"has_forms": true,
		},
	})
}

func (p *webscopeJSONLParser) processJSFile(result *Result, rec webscopeRecord, trigger graph.Node, seen map[string]bool) {
	if rec.URL == "" {
		return
	}

	// JSFile composite key is (url, sha256).
	hash := rec.SHA256
	if hash == "" {
		hash = "unknown"
	}
	key := fmt.Sprintf("%s|%s", rec.URL, hash)

	if seen[key] {
		return
	}
	seen[key] = true

	result.Nodes = append(result.Nodes, graph.Node{
		Type:       graph.NodeJSFile,
		PrimaryKey: key,
		Props: map[string]any{
			"url":    rec.URL,
			"sha256": hash,
			"size":   rec.Size,
		},
	})

	// LOADS edge from the triggering URL.
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

func (p *webscopeJSONLParser) processFinding(result *Result, rec webscopeRecord, trigger graph.Node) {
	if rec.FindingType == "" {
		return
	}

	sev := rec.Severity
	if sev == "" {
		sev = "info"
	}

	result.Findings = append(result.Findings, graph.Finding{
		ID:         fmt.Sprintf("webscope-%s-%s", rec.FindingType, trigger.PrimaryKey),
		Type:       rec.FindingType,
		Title:      rec.FindingTitle,
		Severity:   sev,
		Confidence: "tentative",
		Tool:       "webscope",
		Evidence:   rec.Evidence,
		FirstSeen:  time.Now().UTC(),
		LastSeen:   time.Now().UTC(),
	})
}
