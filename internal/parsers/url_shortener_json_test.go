package parsers

import (
	"context"
	"strings"
	"testing"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

func TestURLShortenerJSONParser_Basic(t *testing.T) {
	p := &urlShortenerJSONParser{}
	trigger := graph.Node{Type: graph.NodeDomain, PrimaryKey: "example.com", Props: map[string]any{"fqdn": "example.com"}}
	stdout := `{"engine":"google","query":"site:bit.ly example.com","short_url":"https://bit.ly/abc","final_url":"https://api.example.com/v1/x","class":"shortener-resolved-asset","rank":1,"chain_length":2}`
	out, err := p.Parse(context.Background(), trigger, strings.NewReader(stdout), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(out.Nodes) != 1 || len(out.Findings) != 1 {
		t.Fatalf("expected node+finding, got nodes=%d findings=%d", len(out.Nodes), len(out.Findings))
	}
}
