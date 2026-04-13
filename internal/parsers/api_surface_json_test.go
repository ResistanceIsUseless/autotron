package parsers

import (
	"context"
	"strings"
	"testing"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

func TestAPISurfaceJSONParser_Defaults(t *testing.T) {
	p := &apiSurfaceJSONParser{}
	trigger := graph.Node{Type: graph.NodeURL, PrimaryKey: "https://api.example.com", Props: map[string]any{"url": "https://api.example.com"}}

	stdout := `{"finding":"graphql-introspection-enabled","details":"introspection true"}`
	out, err := p.Parse(context.Background(), trigger, strings.NewReader(stdout), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(out.Nodes) == 0 {
		t.Fatal("expected endpoint node from defaults")
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(out.Findings))
	}
}
