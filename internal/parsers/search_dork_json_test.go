package parsers

import (
	"context"
	"strings"
	"testing"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

func TestSearchDorkJSONParser_SeverityMapping(t *testing.T) {
	p := &searchDorkJSONParser{}
	trigger := graph.Node{Type: graph.NodeDomain, PrimaryKey: "example.com", Props: map[string]any{"fqdn": "example.com"}}

	stdout := strings.Join([]string{
		`{"engine":"google","query":"site:example.com intext:apikey","url":"https://app.example.com/test","class":"indexed-secret"}`,
		`{"engine":"google","query":"site:example.com inurl:admin","url":"https://app.example.com/admin","class":"indexed-admin-surface"}`,
	}, "\n")

	out, err := p.Parse(context.Background(), trigger, strings.NewReader(stdout), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(out.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(out.Findings))
	}

	if out.Findings[0].Severity != "high" {
		t.Fatalf("expected first finding high severity, got %s", out.Findings[0].Severity)
	}
	if out.Findings[1].Severity != "medium" {
		t.Fatalf("expected second finding medium severity, got %s", out.Findings[1].Severity)
	}
}
