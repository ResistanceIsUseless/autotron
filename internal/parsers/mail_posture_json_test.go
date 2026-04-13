package parsers

import (
	"context"
	"strings"
	"testing"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

func TestMailPostureJSONParser_DefaultSeverity(t *testing.T) {
	p := &mailPostureJSONParser{}
	trigger := graph.Node{Type: graph.NodeDomain, PrimaryKey: "example.com", Props: map[string]any{"fqdn": "example.com"}}
	out, err := p.Parse(context.Background(), trigger, strings.NewReader(`{"type":"missing-dmarc","details":"none"}`), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(out.Findings))
	}
	if out.Findings[0].Severity != "medium" {
		t.Fatalf("expected medium default severity, got %s", out.Findings[0].Severity)
	}
}
