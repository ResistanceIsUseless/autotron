package parsers

import (
	"context"
	"strings"
	"testing"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

func TestExposurePassiveJSONParser_SeverityFallback(t *testing.T) {
	p := &exposurePassiveJSONParser{}
	trigger := graph.Node{Type: graph.NodeSubdomain, PrimaryKey: "test.example.com", Props: map[string]any{"fqdn": "test.example.com", "ips": "1.2.3.4"}}

	stdout := `{"provider":"censys","ip":"1.2.3.4","port":8443,"protocol":"tcp","service":"https","risk":"unknown"}`
	out, err := p.Parse(context.Background(), trigger, strings.NewReader(stdout), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(out.Findings))
	}
	if out.Findings[0].Severity != "info" {
		t.Fatalf("expected info severity fallback, got %s", out.Findings[0].Severity)
	}
}
