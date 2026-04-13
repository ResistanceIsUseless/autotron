package parsers

import (
	"context"
	"strings"
	"testing"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

func TestDeltaReportJSONParser_SuccessAndMalformedAndEmpty(t *testing.T) {
	p := &deltaReportJSONParser{}
	trigger := graph.Node{Type: graph.NodeScanRun, PrimaryKey: "run-2", Props: map[string]any{"id": "run-2"}}

	stdout := `{"type":"delta-new-findings","title":"Findings increased","severity":"high","confidence":"firm","details":"findings grew from 10 to 30","metric":"findings","current_count":30,"previous_count":10,"current_scan_run_id":"run-2","previous_scan_run_id":"run-1"}
{bad
{"type":""}`

	out, err := p.Parse(context.Background(), trigger, strings.NewReader(stdout), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out.Findings))
	}

	empty, err := p.Parse(context.Background(), trigger, strings.NewReader("\n"), strings.NewReader(""))
	if err != nil {
		t.Fatalf("empty parse failed: %v", err)
	}
	if len(empty.Findings) != 0 {
		t.Fatalf("expected no findings for empty parse, got %d", len(empty.Findings))
	}
}
