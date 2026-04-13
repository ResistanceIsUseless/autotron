package parsers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

type jsreconJSONParser struct{}

func init() {
	Register(&jsreconJSONParser{})
}

func (p *jsreconJSONParser) Name() string { return "jsrecon_json" }

type jsreconOutput struct {
	Findings []jsreconFinding `json:"findings"`
	Stats    jsreconStats     `json:"stats"`
	Error    string           `json:"error"`
}

type jsreconStats struct {
	DurationMS int `json:"duration_ms"`
}

type jsreconFinding struct {
	Type       string         `json:"type"`
	Subtype    string         `json:"subtype"`
	Value      string         `json:"value"`
	Line       int            `json:"line"`
	Col        int            `json:"col"`
	Confidence float64        `json:"confidence"`
	Context    string         `json:"context"`
	Metadata   map[string]any `json:"metadata"`
}

func (p *jsreconJSONParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var output jsreconOutput
	if err := json.NewDecoder(stdout).Decode(&output); err != nil {
		return Result{}, fmt.Errorf("decode jsrecon JSON: %w", err)
	}

	if output.Error != "" {
		return Result{}, fmt.Errorf("jsrecon error: %s", output.Error)
	}

	var result Result
	now := time.Now().UTC()
	seenEndpoints := make(map[string]bool)
	seenDomains := make(map[string]bool)
	jsURL := strings.TrimSpace(trigger.PrimaryKey)
	parentURL, _ := trigger.Props["url"].(string)

	for i, f := range output.Findings {
		typeLower := strings.ToLower(strings.TrimSpace(f.Type))
		subtypeLower := strings.ToLower(strings.TrimSpace(f.Subtype))
		value := strings.TrimSpace(f.Value)

		switch typeLower {
		case "path", "route_definition", "graphql", "call_pattern":
			if value != "" {
				method := inferHTTPMethod(subtypeLower)
				endpointURL, endpointPath := buildEndpointLocation(parentURL, value)
				if endpointPath != "" {
					key := endpointID(endpointURL, method, endpointPath)
					if !seenEndpoints[key] {
						seenEndpoints[key] = true
						result.Nodes = append(result.Nodes, graph.Node{
							Type:       graph.NodeEndpoint,
							PrimaryKey: key,
							Props: map[string]any{
								"endpoint_id": key,
								"url":         endpointURL,
								"method":      method,
								"path":        endpointPath,
								"source":      "jsrecon",
								"kind":        typeLower,
								"subtype":     subtypeLower,
							},
						})

						if trigger.Type == graph.NodeJSFile && parentURL != "" {
							result.Edges = append(result.Edges, graph.Edge{
								Type:     graph.RelEXPOSES,
								FromType: graph.NodeURL,
								FromKey:  parentURL,
								ToType:   graph.NodeEndpoint,
								ToKey:    key,
							})
						}
					}
				}
			}
		}

		for _, domain := range extractDomains(value, f.Metadata) {
			fqdn := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
			if fqdn == "" || seenDomains[fqdn] {
				continue
			}
			seenDomains[fqdn] = true
			result.Nodes = append(result.Nodes, graph.Node{
				Type:       graph.NodeSubdomain,
				PrimaryKey: fqdn,
				Props: map[string]any{
					"fqdn":   fqdn,
					"status": "discovered",
					"source": "jsrecon",
				},
			})
		}

		sev, conf := findingRisk(typeLower, subtypeLower, f.Confidence)
		findingType := fmt.Sprintf("jsrecon-%s", typeLower)
		if subtypeLower != "" {
			findingType = fmt.Sprintf("jsrecon-%s-%s", typeLower, subtypeLower)
		}

		evidence := map[string]any{
			"value":      value,
			"type":       typeLower,
			"subtype":    subtypeLower,
			"line":       f.Line,
			"col":        f.Col,
			"confidence": f.Confidence,
			"js_url":     jsURL,
		}
		if len(f.Metadata) > 0 {
			evidence["metadata"] = f.Metadata
		}

		result.Findings = append(result.Findings, graph.Finding{
			ID:         fmt.Sprintf("jsrecon-%s-%d-%s", hashKey(jsURL), i, hashKey(typeLower+"|"+subtypeLower+"|"+value)),
			Type:       findingType,
			Title:      fmt.Sprintf("jsRecon %s: %s", typeLower, summarizeValue(value, 120)),
			Severity:   sev,
			Confidence: conf,
			Tool:       "jsrecon",
			Evidence:   evidence,
			FirstSeen:  now,
			LastSeen:   now,
		})
	}

	return result, nil
}

func inferHTTPMethod(subtype string) string {
	s := strings.ToLower(subtype)
	switch {
	case strings.Contains(s, "post"):
		return "POST"
	case strings.Contains(s, "put"):
		return "PUT"
	case strings.Contains(s, "patch"):
		return "PATCH"
	case strings.Contains(s, "delete"):
		return "DELETE"
	default:
		return "GET"
	}
}

func buildEndpointLocation(parentURL, value string) (baseURL, pathValue string) {
	v := strings.TrimSpace(value)
	if v == "" {
		return parentURL, ""
	}

	if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
		u, err := url.Parse(v)
		if err == nil {
			baseURL = u.Scheme + "://" + u.Host
			pathValue = u.Path
			if pathValue == "" {
				pathValue = "/"
			}
			if u.RawQuery != "" {
				pathValue += "?" + u.RawQuery
			}
			return baseURL, pathValue
		}
	}

	pathValue = v
	if !strings.HasPrefix(pathValue, "/") {
		pathValue = "/" + pathValue
	}
	if parentURL == "" {
		parentURL = "https://unknown"
	}
	return parentURL, pathValue
}

func extractDomains(value string, metadata map[string]any) []string {
	out := []string{}
	if v := strings.TrimSpace(value); v != "" {
		if d := domainFromString(v); d != "" {
			out = append(out, d)
		}
	}
	for _, candidate := range metadataStringValues(metadata) {
		if d := domainFromString(candidate); d != "" {
			out = append(out, d)
		}
	}
	return out
}

func metadataStringValues(m map[string]any) []string {
	if len(m) == 0 {
		return nil
	}
	var out []string
	for _, v := range m {
		switch x := v.(type) {
		case string:
			out = append(out, x)
		case []any:
			for _, item := range x {
				if s, ok := item.(string); ok {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

func domainFromString(s string) string {
	v := strings.TrimSpace(s)
	if v == "" {
		return ""
	}
	if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
		u, err := url.Parse(v)
		if err == nil {
			return u.Hostname()
		}
	}
	if strings.Contains(v, ".") && !strings.Contains(v, " ") && !strings.Contains(v, "/") {
		return strings.TrimSuffix(v, ".")
	}
	return ""
}

func findingRisk(ftype, subtype string, rawConfidence float64) (severity, confidence string) {
	confidence = "tentative"
	if rawConfidence >= 0.85 {
		confidence = "confirmed"
	} else if rawConfidence >= 0.6 {
		confidence = "firm"
	}

	severity = "low"
	s := strings.ToLower(ftype + "|" + subtype)
	switch {
	case strings.Contains(s, "secret"):
		severity = "high"
	case strings.Contains(s, "vulnerability"):
		severity = "medium"
	case strings.Contains(s, "xss") || strings.Contains(s, "prototype_pollution"):
		severity = "high"
	case strings.Contains(s, "open_redirect") || strings.Contains(s, "cors"):
		severity = "medium"
	case strings.Contains(s, "path") || strings.Contains(s, "route_definition"):
		severity = "info"
	case strings.Contains(s, "graphql") || strings.Contains(s, "call_pattern"):
		severity = "low"
	case strings.Contains(s, "client_behavior"):
		severity = "info"
	}
	return severity, confidence
}

func summarizeValue(v string, max int) string {
	v = strings.TrimSpace(v)
	if len(v) <= max {
		return v
	}
	return v[:max] + "..."
}
