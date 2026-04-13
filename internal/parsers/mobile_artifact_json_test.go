package parsers

import (
	"context"
	"strings"
	"testing"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

func TestMobileArtifactJSONParser_SuccessAndMalformedAndEmpty(t *testing.T) {
	p := &mobileArtifactJSONParser{}
	trigger := graph.Node{Type: graph.NodeURL, PrimaryKey: "https://cdn.example.com/app.apk", Props: map[string]any{"url": "https://cdn.example.com/app.apk"}}

	stdout := `{"artifact_url":"https://cdn.example.com/app.apk","artifact_type":"apk","endpoint_url":"https://api.example.com/v1/users","method":"POST","path":"/v1/users","finding":"mobile-endpoint-discovered","severity":"medium","confidence":"firm","details":"Found API URL","evidence":"https://api.example.com/v1/users"}
not-json
{"finding":""}`

	out, err := p.Parse(context.Background(), trigger, strings.NewReader(stdout), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(out.Nodes) != 1 {
		t.Fatalf("expected 1 endpoint node, got %d", len(out.Nodes))
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out.Findings))
	}

	empty, err := p.Parse(context.Background(), trigger, strings.NewReader("\n\n"), strings.NewReader(""))
	if err != nil {
		t.Fatalf("empty parse failed: %v", err)
	}
	if len(empty.Nodes) != 0 || len(empty.Findings) != 0 {
		t.Fatalf("expected no output for empty parse, got nodes=%d findings=%d", len(empty.Nodes), len(empty.Findings))
	}
}
