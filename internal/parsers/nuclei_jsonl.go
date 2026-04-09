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

// nucleiJSONLParser handles nuclei JSONL output across all template variants:
// takeover checks, network templates, web vulnerability scans, CVE detection.
//
// nuclei -jsonl outputs one JSON object per finding. The parser normalizes
// these into Finding nodes rooted on the trigger (URL, Service, or Subdomain).
type nucleiJSONLParser struct{}

func init() {
	Register(&nucleiJSONLParser{})
}

func (p *nucleiJSONLParser) Name() string { return "nuclei_jsonl" }

// nucleiRecord represents a single nuclei JSONL output line.
type nucleiRecord struct {
	TemplateID string     `json:"template-id"`
	Template   string     `json:"template"`
	Info       nucleiInfo `json:"info"`
	Type       string     `json:"type"` // "http", "dns", "network", "ssl", etc.
	Host       string     `json:"host"`
	Matched    string     `json:"matched-at"`
	IP         string     `json:"ip"`
	Timestamp  string     `json:"timestamp"`
	CurlCmd    string     `json:"curl-command"`
	MatcherSt  string     `json:"matcher-status"`
	ExtractRes []string   `json:"extracted-results"`
	Request    string     `json:"request"`
	Response   string     `json:"response"`
}

type nucleiInfo struct {
	Name           string               `json:"name"`
	Author         []string             `json:"author"`
	Tags           []string             `json:"tags"`
	Description    string               `json:"description"`
	Reference      []string             `json:"reference"`
	Severity       string               `json:"severity"` // "info", "low", "medium", "high", "critical"
	Metadata       map[string]any       `json:"metadata"`
	Classification nucleiClassification `json:"classification"`
}

type nucleiClassification struct {
	CVE  []string `json:"cve-id"`
	CWE  []string `json:"cwe-id"`
	CVSS float64  `json:"cvss-score"`
}

func (p *nucleiJSONLParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var result Result
	now := time.Now().UTC()
	seenFindings := make(map[string]bool)

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 2*1024*1024), 2*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var rec nucleiRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}

		if rec.TemplateID == "" || rec.Info.Name == "" {
			continue
		}

		// Build a deterministic finding ID.
		findingID := fmt.Sprintf("nuclei-%s-%s", rec.TemplateID, hashKey(rec.Matched+rec.Host))
		if seenFindings[findingID] {
			continue
		}
		seenFindings[findingID] = true

		severity := strings.ToLower(rec.Info.Severity)
		if severity == "" {
			severity = "info"
		}

		// Build evidence map.
		evidence := map[string]any{
			"template_id": rec.TemplateID,
			"matched_at":  rec.Matched,
			"host":        rec.Host,
			"type":        rec.Type,
		}
		if rec.IP != "" {
			evidence["ip"] = rec.IP
		}
		if len(rec.ExtractRes) > 0 {
			evidence["extracted_results"] = rec.ExtractRes
		}
		if len(rec.Info.Tags) > 0 {
			evidence["tags"] = rec.Info.Tags
		}
		if len(rec.Info.Author) > 0 {
			evidence["author"] = rec.Info.Author
		}
		if len(rec.Info.Reference) > 0 {
			evidence["references"] = rec.Info.Reference
		}
		if rec.Info.Description != "" {
			evidence["description"] = rec.Info.Description
		}
		if rec.Info.Classification.CVSS > 0 {
			evidence["cvss_score"] = rec.Info.Classification.CVSS
		}

		// Determine finding type from template ID and tags.
		findingType := p.classifyFinding(rec)

		// CVE/CWE extraction.
		var cves, cwes []string
		if len(rec.Info.Classification.CVE) > 0 {
			cves = rec.Info.Classification.CVE
		}
		if len(rec.Info.Classification.CWE) > 0 {
			cwes = rec.Info.Classification.CWE
		}

		result.Findings = append(result.Findings, graph.Finding{
			ID:         findingID,
			Type:       findingType,
			Title:      rec.Info.Name,
			Severity:   severity,
			Confidence: "firm", // nuclei template matches are generally reliable
			Tool:       "nuclei",
			CVE:        cves,
			CWE:        cwes,
			Evidence:   evidence,
			FirstSeen:  now,
			LastSeen:   now,
		})
	}

	return result, scanner.Err()
}

// classifyFinding derives a finding type from the nuclei template ID and tags.
func (p *nucleiJSONLParser) classifyFinding(rec nucleiRecord) string {
	tid := strings.ToLower(rec.TemplateID)
	tags := rec.Info.Tags

	// Check for specific categories.
	for _, tag := range tags {
		switch strings.ToLower(tag) {
		case "takeover", "subdomain-takeover":
			return "subdomain-takeover"
		case "cve":
			if len(rec.Info.Classification.CVE) > 0 {
				return fmt.Sprintf("cve-%s", strings.ToLower(rec.Info.Classification.CVE[0]))
			}
			return "cve"
		case "misconfig":
			return "misconfiguration"
		case "exposure", "exposed":
			return "exposure"
		case "xss":
			return "xss"
		case "sqli":
			return "sqli"
		case "ssrf":
			return "ssrf"
		case "lfi", "rfi":
			return "file-inclusion"
		case "rce":
			return "rce"
		}
	}

	// Fall back to template ID prefix.
	if strings.Contains(tid, "takeover") {
		return "subdomain-takeover"
	}
	if strings.Contains(tid, "cve-") {
		return "cve"
	}

	return fmt.Sprintf("nuclei-%s", tid)
}
