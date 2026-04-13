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

type apiSurfaceJSONParser struct{}

func init() {
	Register(&apiSurfaceJSONParser{})
}

func (p *apiSurfaceJSONParser) Name() string { return "api_surface_json" }

type apiSurfaceRecord struct {
	BaseURL    string   `json:"base_url"`
	Method     string   `json:"method"`
	Path       string   `json:"path"`
	Params     []string `json:"params"`
	Finding    string   `json:"finding"`
	Severity   string   `json:"severity"`
	Confidence string   `json:"confidence"`
	Details    string   `json:"details"`
}

func (p *apiSurfaceJSONParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var out Result

	s := bufio.NewScanner(stdout)
	s.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var rec apiSurfaceRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}

		base := strings.TrimSpace(rec.BaseURL)
		if base == "" {
			base = trigger.PrimaryKey
		}
		path := strings.TrimSpace(rec.Path)
		if path == "" {
			path = "/"
		}
		method := strings.ToUpper(strings.TrimSpace(rec.Method))
		if method == "" {
			method = "GET"
		}

		eid := endpointID(base, method, path)
		out.Nodes = append(out.Nodes, graph.Node{
			Type:       graph.NodeEndpoint,
			PrimaryKey: eid,
			Props: map[string]any{
				"endpoint_id": eid,
				"url":         base,
				"method":      method,
				"path":        path,
				"params":      rec.Params,
				"source":      "api-surface",
			},
		})
		out.Edges = append(out.Edges, graph.Edge{
			Type:     graph.RelEXPOSES,
			FromType: graph.NodeURL,
			FromKey:  base,
			ToType:   graph.NodeEndpoint,
			ToKey:    eid,
		})

		fType := strings.TrimSpace(strings.ToLower(rec.Finding))
		if fType == "" {
			continue
		}
		sev := strings.ToLower(strings.TrimSpace(rec.Severity))
		if sev == "" {
			sev = "medium"
		}
		conf := strings.ToLower(strings.TrimSpace(rec.Confidence))
		if conf == "" {
			conf = "firm"
		}

		fid := fmt.Sprintf("api-%s", hashKey(eid+"|"+fType+"|"+rec.Details))
		out.Findings = append(out.Findings, graph.Finding{
			ID:         fid,
			Type:       fType,
			Title:      fmt.Sprintf("API surface finding: %s", fType),
			Severity:   sev,
			Confidence: conf,
			Tool:       "api-surface",
			Evidence: map[string]any{
				"url":     base,
				"method":  method,
				"path":    path,
				"details": rec.Details,
			},
			FirstSeen: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
		})
	}

	if err := s.Err(); err != nil {
		return Result{}, err
	}
	return out, nil
}
