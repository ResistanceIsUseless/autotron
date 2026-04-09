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

// secretScannerParser handles secret scanning tools: trufflehog, gitleaks.
//
// Formats handled:
//   - trufflehog JSON (--json): one JSON object per line with detector, raw, source
//   - gitleaks JSON (--report-format json): array of objects with rule, match, file
//
// Emits: Finding nodes rooted on the trigger URL/JSFile.
type secretScannerParser struct{}

func init() {
	Register(&secretScannerParser{})
}

func (p *secretScannerParser) Name() string { return "secret_scanner" }

// trufflehogResult represents a single trufflehog JSON line.
type trufflehogResult struct {
	DetectorName string `json:"DetectorName"`
	DecoderName  string `json:"DecoderName"`
	Verified     bool   `json:"Verified"`
	Raw          string `json:"Raw"`
	RawV2        string `json:"RawV2"`
	SourceID     int    `json:"SourceID"`
	SourceName   string `json:"SourceName"`
	SourceType   int    `json:"SourceType"`
	// Extra metadata (varies by detector).
	ExtraData map[string]any `json:"ExtraData"`
}

// gitleaksResult represents a single gitleaks finding.
type gitleaksResult struct {
	RuleID      string `json:"RuleID"`
	Description string `json:"Description"`
	Match       string `json:"Match"`
	Secret      string `json:"Secret"`
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	Commit      string `json:"Commit"`
	Author      string `json:"Author"`
	Email       string `json:"Email"`
	Date        string `json:"Date"`
	Fingerprint string `json:"Fingerprint"`
}

func (p *secretScannerParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var result Result
	now := time.Now().UTC()

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	var lines []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return result, err
	}

	if len(lines) == 0 {
		return result, nil
	}

	// Detect format: trufflehog emits JSONL (one object per line with DetectorName),
	// gitleaks emits a JSON array.
	fullOutput := strings.Join(lines, "\n")

	// Try gitleaks array format first.
	if strings.HasPrefix(strings.TrimSpace(fullOutput), "[") {
		p.parseGitleaks(fullOutput, trigger, &result, now)
		return result, nil
	}

	// Try trufflehog JSONL.
	for i, line := range lines {
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var rec trufflehogResult
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec.DetectorName == "" {
			continue
		}

		severity := "high"
		confidence := "tentative"
		if rec.Verified {
			severity = "critical"
			confidence = "confirmed"
		}

		evidence := map[string]any{
			"detector":    rec.DetectorName,
			"source_name": rec.SourceName,
		}
		if rec.DecoderName != "" {
			evidence["decoder"] = rec.DecoderName
		}
		if rec.ExtraData != nil {
			evidence["extra"] = rec.ExtraData
		}
		// Redact raw value — store truncated indicator only.
		if rec.Raw != "" {
			evidence["raw_length"] = len(rec.Raw)
			if len(rec.Raw) > 8 {
				evidence["raw_prefix"] = rec.Raw[:4] + "****"
			}
		}

		findingID := fmt.Sprintf("trufflehog-%s-%s-%d", rec.DetectorName, hashKey(trigger.PrimaryKey), i)
		result.Findings = append(result.Findings, graph.Finding{
			ID:         findingID,
			Type:       fmt.Sprintf("secret-%s", strings.ToLower(rec.DetectorName)),
			Title:      fmt.Sprintf("Secret detected: %s", rec.DetectorName),
			Severity:   severity,
			Confidence: confidence,
			Tool:       "trufflehog",
			Evidence:   evidence,
			FirstSeen:  now,
			LastSeen:   now,
		})
	}

	return result, nil
}

func (p *secretScannerParser) parseGitleaks(data string, trigger graph.Node, result *Result, now time.Time) {
	var findings []gitleaksResult
	if err := json.Unmarshal([]byte(data), &findings); err != nil {
		return
	}

	for i, f := range findings {
		if f.RuleID == "" {
			continue
		}

		evidence := map[string]any{
			"rule_id": f.RuleID,
			"file":    f.File,
			"line":    f.StartLine,
		}
		if f.Commit != "" {
			evidence["commit"] = f.Commit
		}
		if f.Fingerprint != "" {
			evidence["fingerprint"] = f.Fingerprint
		}
		// Redact the actual secret.
		if f.Secret != "" {
			evidence["secret_length"] = len(f.Secret)
			if len(f.Secret) > 8 {
				evidence["secret_prefix"] = f.Secret[:4] + "****"
			}
		}

		findingID := fmt.Sprintf("gitleaks-%s-%s-%d", f.RuleID, hashKey(trigger.PrimaryKey), i)
		result.Findings = append(result.Findings, graph.Finding{
			ID:         findingID,
			Type:       fmt.Sprintf("secret-%s", strings.ToLower(f.RuleID)),
			Title:      fmt.Sprintf("Secret detected: %s", f.Description),
			Severity:   "high",
			Confidence: "firm",
			Tool:       "gitleaks",
			Evidence:   evidence,
			FirstSeen:  now,
			LastSeen:   now,
		})
	}
}

// hashKey returns a short hash of a string for use in finding IDs.
// Uses a simple FNV-like approach for deterministic, short IDs.
func hashKey(s string) string {
	h := uint32(2166136261) // FNV-1a offset basis
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619 // FNV-1a prime
	}
	return fmt.Sprintf("%08x", h)
}
