package parsers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

type mobileArtifactJSONParser struct{}

func init() {
	Register(&mobileArtifactJSONParser{})
}

func (p *mobileArtifactJSONParser) Name() string { return "mobile_artifact_json" }

type mobileArtifactRecord struct {
	ArtifactURL  string `json:"artifact_url"`
	ArtifactType string `json:"artifact_type"`
	EndpointURL  string `json:"endpoint_url"`
	Method       string `json:"method"`
	Path         string `json:"path"`
	Finding      string `json:"finding"`
	Severity     string `json:"severity"`
	Confidence   string `json:"confidence"`
	Details      string `json:"details"`
	Evidence     string `json:"evidence"`
}

func (p *mobileArtifactJSONParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var out Result
	seenEndpoint := make(map[string]bool)

	s := bufio.NewScanner(stdout)
	s.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var rec mobileArtifactRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}

		target := strings.TrimSpace(rec.EndpointURL)
		if target != "" {
			if parsed, err := url.Parse(target); err == nil && parsed.Scheme != "" && parsed.Host != "" {
				base := parsed.Scheme + "://" + parsed.Host
				method := strings.ToUpper(strings.TrimSpace(rec.Method))
				if method == "" {
					method = "GET"
				}

				path := strings.TrimSpace(rec.Path)
				if path == "" {
					path = strings.TrimSpace(parsed.EscapedPath())
				}
				if path == "" {
					path = "/"
				}

				eid := endpointID(base, method, path)
				if !seenEndpoint[eid] {
					seenEndpoint[eid] = true
					out.Nodes = append(out.Nodes, graph.Node{
						Type:       graph.NodeEndpoint,
						PrimaryKey: eid,
						Props: map[string]any{
							"endpoint_id":   eid,
							"url":           base,
							"method":        method,
							"path":          path,
							"source":        "mobile-artifact",
							"artifact_type": strings.ToLower(strings.TrimSpace(rec.ArtifactType)),
						},
					})
					if trigger.Type == graph.NodeURL {
						out.Edges = append(out.Edges, graph.Edge{
							Type:     graph.RelEXPOSES,
							FromType: graph.NodeURL,
							FromKey:  trigger.PrimaryKey,
							ToType:   graph.NodeEndpoint,
							ToKey:    eid,
						})
					}
				}
			}
		}

		findingType := strings.ToLower(strings.TrimSpace(rec.Finding))
		if findingType == "" {
			if target == "" {
				continue
			}
			findingType = "mobile-endpoint-discovered"
		}

		severity := normalizeSeverity(rec.Severity, "low")
		confidence := normalizeConfidence(rec.Confidence, "tentative")
		title := strings.TrimSpace(rec.Details)
		if title == "" {
			title = fmt.Sprintf("Mobile artifact finding: %s", findingType)
		}

		fid := fmt.Sprintf("mobile-%s", hashKey(trigger.PrimaryKey+"|"+target+"|"+findingType+"|"+rec.Evidence+"|"+rec.Details))
		out.Findings = append(out.Findings, graph.Finding{
			ID:         fid,
			Type:       findingType,
			Title:      title,
			Severity:   severity,
			Confidence: confidence,
			Tool:       "mobile-artifact",
			Evidence: map[string]any{
				"artifact_url":  fallbackString(rec.ArtifactURL, trigger.PrimaryKey),
				"artifact_type": strings.ToLower(strings.TrimSpace(rec.ArtifactType)),
				"endpoint_url":  target,
				"method":        strings.ToUpper(strings.TrimSpace(rec.Method)),
				"path":          rec.Path,
				"details":       rec.Details,
				"evidence":      rec.Evidence,
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

func normalizeSeverity(v string, fallback string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "info", "low", "medium", "high", "critical":
		return v
	default:
		return fallback
	}
}

func normalizeConfidence(v string, fallback string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "tentative", "firm", "confirmed":
		return v
	default:
		return fallback
	}
}
