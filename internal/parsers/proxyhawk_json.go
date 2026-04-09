package parsers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

// proxyhawkJSONParser handles the custom proxyhawk tool's JSON output.
// proxyhawk tests URLs for SSRF, open redirects, and related proxy-abuse vulnerabilities.
//
// Emits: Finding nodes rooted on the trigger URL.
type proxyhawkJSONParser struct{}

func init() {
	Register(&proxyhawkJSONParser{})
}

func (p *proxyhawkJSONParser) Name() string { return "proxyhawk_json" }

// proxyhawkOutput represents the expected JSON output from proxyhawk.
type proxyhawkOutput struct {
	URL      string             `json:"url"`
	Findings []proxyhawkFinding `json:"findings"`
}

type proxyhawkFinding struct {
	Type       string `json:"type"`        // "ssrf", "open-redirect", "header-injection", etc.
	Param      string `json:"param"`       // vulnerable parameter
	Payload    string `json:"payload"`     // payload that triggered the finding
	Evidence   string `json:"evidence"`    // response snippet proving the vuln
	Severity   string `json:"severity"`    // info|low|medium|high|critical
	Confidence string `json:"confidence"`  // tentative|firm|confirmed
	StatusCode int    `json:"status_code"` // HTTP response code
}

func (p *proxyhawkJSONParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var output proxyhawkOutput
	if err := json.NewDecoder(stdout).Decode(&output); err != nil {
		return Result{}, fmt.Errorf("decode proxyhawk JSON: %w", err)
	}

	var result Result
	now := time.Now().UTC()

	for i, f := range output.Findings {
		if f.Type == "" {
			continue
		}

		severity := f.Severity
		if severity == "" {
			severity = p.defaultSeverity(f.Type)
		}
		confidence := f.Confidence
		if confidence == "" {
			confidence = "firm"
		}

		evidence := map[string]any{
			"url":   output.URL,
			"param": f.Param,
		}
		if f.Payload != "" {
			evidence["payload"] = f.Payload
		}
		if f.Evidence != "" {
			evidence["response_evidence"] = f.Evidence
		}
		if f.StatusCode > 0 {
			evidence["status_code"] = f.StatusCode
		}

		findingID := fmt.Sprintf("proxyhawk-%s-%s-%d", f.Type, hashKey(output.URL), i)
		result.Findings = append(result.Findings, graph.Finding{
			ID:         findingID,
			Type:       f.Type,
			Title:      fmt.Sprintf("%s in %s (param: %s)", p.titleFor(f.Type), output.URL, f.Param),
			Severity:   severity,
			Confidence: confidence,
			Tool:       "proxyhawk",
			Evidence:   evidence,
			FirstSeen:  now,
			LastSeen:   now,
		})
	}

	return result, nil
}

func (p *proxyhawkJSONParser) defaultSeverity(findingType string) string {
	switch strings.ToLower(findingType) {
	case "ssrf":
		return "high"
	case "open-redirect":
		return "medium"
	case "header-injection":
		return "medium"
	default:
		return "medium"
	}
}

func (p *proxyhawkJSONParser) titleFor(findingType string) string {
	switch strings.ToLower(findingType) {
	case "ssrf":
		return "Server-Side Request Forgery"
	case "open-redirect":
		return "Open Redirect"
	case "header-injection":
		return "Header Injection"
	default:
		return strings.ReplaceAll(strings.Title(findingType), "-", " ")
	}
}
