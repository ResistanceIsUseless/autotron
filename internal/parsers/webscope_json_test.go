package parsers

import (
	"context"
	"strings"
	"testing"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

func TestWebscopeJSONParser(t *testing.T) {
	sample := `{"target":"https://dropzone.example.com","flow":"in-depth","paths":[{"url":"https://dropzone.example.com","status":200,"method":"GET","content_type":"text/html","source":"basic"},{"url":"https://dropzone.example.com/robots.txt","status":200,"method":"GET","content_type":"text/plain","source":"basic-common"},{"url":"https://dropzone.example.com/static/app.min.js","status":200,"method":"GET","content_type":"application/javascript","source":"deep-katana"},{"url":"https://dropzone.example.com/static/vendor.mjs","status":200,"method":"GET","content_type":"application/javascript","source":"deep-katana"}],"endpoints":[{"path":"/robots.txt","type":"common","method":"GET","source":"basic"},{"path":"/api/upload","type":"discovered","method":"POST","source":"deep-katana"}],"findings":[{"url":"https://dropzone.example.com/.env","type":"sensitive-path","severity":"high","details":"Potentially sensitive path discovered"}],"stats":{"requests_total":50,"requests_success":48}}`

	p := &webscopeJSONParser{}
	trigger := graph.Node{
		Type:       graph.NodeService,
		PrimaryKey: "dropzone.example.com:443",
		Props:      map[string]any{"fqdn": "dropzone.example.com", "port": "443", "product": "https"},
	}

	result, err := p.Parse(context.Background(), trigger, strings.NewReader(sample), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	// 4 paths → 4 URL nodes + 2 JS files (app.min.js, vendor.mjs) → 2 JSFile nodes + 2 endpoints → 2 Endpoint nodes = 8 nodes
	urlCount, jsCount, epCount := 0, 0, 0
	for _, n := range result.Nodes {
		switch n.Type {
		case graph.NodeURL:
			urlCount++
		case graph.NodeJSFile:
			jsCount++
		case graph.NodeEndpoint:
			epCount++
		}
	}

	if urlCount != 4 {
		t.Errorf("expected 4 URL nodes, got %d", urlCount)
	}
	if jsCount != 2 {
		t.Errorf("expected 2 JSFile nodes, got %d", jsCount)
	}
	if epCount != 2 {
		t.Errorf("expected 2 Endpoint nodes, got %d", epCount)
	}

	// 4 EXPOSES (Service→URL) + 2 LOADS (URL→JSFile) + 2 EXPOSES (Service→Endpoint) = 8
	if len(result.Edges) != 8 {
		t.Errorf("expected 8 edges, got %d", len(result.Edges))
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.Type != "sensitive-path" {
		t.Errorf("expected finding type sensitive-path, got %s", f.Type)
	}
	if f.Severity != "high" {
		t.Errorf("expected severity high, got %s", f.Severity)
	}
}

func TestWebscopeJSONParserEmpty(t *testing.T) {
	p := &webscopeJSONParser{}
	trigger := graph.Node{Type: graph.NodeURL, PrimaryKey: "https://example.com"}
	result, err := p.Parse(context.Background(), trigger, strings.NewReader(""), strings.NewReader(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Nodes) != 0 || len(result.Findings) != 0 {
		t.Errorf("expected empty result for empty input")
	}
}
