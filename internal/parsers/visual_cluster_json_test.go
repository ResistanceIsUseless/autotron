package parsers

import (
	"context"
	"strings"
	"testing"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

func TestVisualClusterJSONParser_SuccessAndEmpty(t *testing.T) {
	p := &visualClusterJSONParser{}
	trigger := graph.Node{Type: graph.NodeURL, PrimaryKey: "https://app.example.com", Props: map[string]any{"url": "https://app.example.com"}}

	stdout := `{"url":"https://app.example.com","screenshot_path":"output/screenshots/app.png","cluster_key":"login-panel-01","label":"login","type":"exposed-login-panel","severity":"medium","confidence":"firm","details":"Login panel detected"}`
	out, err := p.Parse(context.Background(), trigger, strings.NewReader(stdout), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(out.Nodes) == 0 || len(out.Findings) == 0 {
		t.Fatalf("expected URL update + finding, got nodes=%d findings=%d", len(out.Nodes), len(out.Findings))
	}

	empty, err := p.Parse(context.Background(), trigger, strings.NewReader("\n"), strings.NewReader(""))
	if err != nil {
		t.Fatalf("empty parse failed: %v", err)
	}
	if len(empty.Findings) != 0 {
		t.Fatalf("expected no findings for empty input, got %d", len(empty.Findings))
	}
}
