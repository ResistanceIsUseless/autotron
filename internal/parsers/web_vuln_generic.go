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

// webVulnGenericParser handles generic web vulnerability scanners:
// nikto, wapiti, dalfox, corsy.
//
// These tools all emit JSON with varying schemas, but share the common pattern
// of producing vulnerability findings rooted on a URL target. The parser
// normalizes all formats into Finding nodes.
//
// Formats handled:
//   - nikto JSON (-Format json): array of objects with id, msg, url, method
//   - wapiti JSON (-f json -o -): structured report with vulnerabilities array
//   - dalfox JSON (--format json): JSONL with type, poc, param, evidence
//   - corsy JSON (-o json): JSONL with url, type, origin, credentials
type webVulnGenericParser struct{}

func init() {
	Register(&webVulnGenericParser{})
}

func (p *webVulnGenericParser) Name() string { return "web_vuln_generic" }

// niktoFinding represents a nikto JSON finding.
type niktoFinding struct {
	ID          any    `json:"id"`
	OSVDBID     string `json:"OSVDB"`
	Method      string `json:"method"`
	URL         string `json:"url"`
	Msg         string `json:"msg"`
	Description string `json:"description"`
	References  any    `json:"references"`
}

// niktoOutput wraps nikto's full JSON output.
type niktoOutput struct {
	Host            string         `json:"host"`
	IP              string         `json:"ip"`
	Port            string         `json:"port"`
	ServerBanner    string         `json:"server_banner"`
	Vulnerabilities []niktoFinding `json:"vulnerabilities"`
}

// wapitiFinding represents a wapiti vulnerability entry.
type wapitiFinding struct {
	Type       string `json:"type"`
	Level      string `json:"level"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Parameter  string `json:"parameter"`
	Info       string `json:"info"`
	HTTPCode   int    `json:"http_resp"`
	CurlCmd    string `json:"curl_command"`
	WapitiType string `json:"wstg"`
}

// dalfoxResult represents a dalfox JSON line.
type dalfoxResult struct {
	Type       string `json:"type"` // "V" (verified), "G" (grepping), "S" (special)
	POC        string `json:"poc"`  // proof of concept URL
	Param      string `json:"param"`
	Payload    string `json:"payload"`
	Evidence   string `json:"evidence"`
	CWE        string `json:"cwe"`
	Severity   string `json:"severity"`
	MessageStr string `json:"message_str"`
}

// corsyResult represents a corsy JSON line.
type corsyResult struct {
	URL         string `json:"url"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Origin      string `json:"origin"`
	Credentials bool   `json:"credentials"`
	Severity    string `json:"severity"`
}

func (p *webVulnGenericParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var result Result
	now := time.Now().UTC()

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 2*1024*1024), 2*1024*1024)

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

	fullOutput := strings.Join(lines, "\n")
	trimmed := strings.TrimSpace(fullOutput)

	// Try nikto format (object with "vulnerabilities" array).
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		if p.parseNikto(trimmed, trigger, &result, now) {
			return result, nil
		}
		if p.parseWapiti(trimmed, trigger, &result, now) {
			return result, nil
		}
	}

	// Try JSONL formats (dalfox, corsy).
	seenFindings := make(map[string]bool)
	for i, line := range lines {
		if !strings.HasPrefix(line, "{") {
			continue
		}

		// Try dalfox.
		var dRec dalfoxResult
		if err := json.Unmarshal([]byte(line), &dRec); err == nil && dRec.Type != "" && dRec.POC != "" {
			p.addDalfoxFinding(&result, dRec, trigger, i, now, seenFindings)
			continue
		}

		// Try corsy.
		var cRec corsyResult
		if err := json.Unmarshal([]byte(line), &cRec); err == nil && cRec.Type != "" {
			p.addCorsyFinding(&result, cRec, trigger, i, now, seenFindings)
			continue
		}
	}

	return result, nil
}

func (p *webVulnGenericParser) parseNikto(data string, trigger graph.Node, result *Result, now time.Time) bool {
	// nikto can output an array of host results or a single object.
	var hosts []niktoOutput
	if err := json.Unmarshal([]byte(data), &hosts); err != nil {
		var single niktoOutput
		if err2 := json.Unmarshal([]byte(data), &single); err2 != nil {
			return false
		}
		hosts = []niktoOutput{single}
	}

	found := false
	for _, host := range hosts {
		for i, vuln := range host.Vulnerabilities {
			if vuln.Msg == "" && vuln.Description == "" {
				continue
			}
			found = true

			title := vuln.Msg
			if title == "" {
				title = vuln.Description
			}

			evidence := map[string]any{
				"nikto_id": asString(vuln.ID),
				"method":   vuln.Method,
				"url":      vuln.URL,
				"host":     host.Host,
				"ip":       host.IP,
				"port":     host.Port,
			}
			if host.ServerBanner != "" {
				evidence["server_banner"] = host.ServerBanner
			}
			if vuln.OSVDBID != "" && vuln.OSVDBID != "0" {
				evidence["osvdb"] = vuln.OSVDBID
			}
			refs := toStringSliceAny(vuln.References)
			if len(refs) > 0 {
				evidence["references"] = refs
			}

			idToken := asString(vuln.ID)
			if strings.TrimSpace(idToken) == "" {
				idToken = "generic"
			}

			findingID := fmt.Sprintf("nikto-%s-%s-%d", idToken, hashKey(trigger.PrimaryKey), i)
			result.Findings = append(result.Findings, graph.Finding{
				ID:         findingID,
				Type:       fmt.Sprintf("nikto-%s", idToken),
				Title:      title,
				Severity:   niktoSeverity(idToken, title),
				Confidence: "tentative",
				Tool:       "nikto",
				Evidence:   evidence,
				FirstSeen:  now,
				LastSeen:   now,
			})

			// Treat Nikto banner-change check as service metadata signal too.
			if idToken == "999962" {
				if oldB, newB, ok := parseBannerChange(title); ok {
					if host.IP != "" && host.Port != "" {
						var portNum int
						if _, err := fmt.Sscanf(host.Port, "%d", &portNum); err == nil && portNum > 0 {
							ipPort := fmt.Sprintf("%s:%d", host.IP, portNum)
							result.Nodes = append(result.Nodes, graph.Node{
								Type:       graph.NodeService,
								PrimaryKey: ipPort,
								Props: map[string]any{
									"ip_port":         ipPort,
									"ip":              host.IP,
									"port":            portNum,
									"server":          newB,
									"banner":          newB,
									"banner_previous": oldB,
								},
							})
						}
					}
				}
			}
		}
	}
	return found
}

func niktoSeverity(idToken, title string) string {
	id := strings.TrimSpace(idToken)
	t := strings.ToLower(strings.TrimSpace(title))

	// Nikto's well-known "banner changed" signal is informative but not critical.
	if id == "999962" || strings.Contains(t, "server banner changed") {
		return "low"
	}

	// Generic Nikto findings default to info unless parser-specific logic promotes.
	return "info"
}

func parseBannerChange(title string) (oldBanner, newBanner string, ok bool) {
	msg := strings.TrimSpace(title)
	if msg == "" {
		return "", "", false
	}

	marker := "Server banner changed from "
	idx := strings.Index(msg, marker)
	if idx < 0 {
		return "", "", false
	}
	rest := strings.TrimSpace(msg[idx+len(marker):])
	parts := strings.SplitN(rest, " to ", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	oldBanner = strings.Trim(parts[0], " '")
	newBanner = strings.Trim(parts[1], " '")
	if oldBanner == "" || newBanner == "" {
		return "", "", false
	}
	return oldBanner, newBanner, true
}

func asString(v any) string {
	return strings.TrimSpace(fmt.Sprintf("%v", v))
}

func toStringSliceAny(v any) []string {
	switch arr := v.(type) {
	case []string:
		out := make([]string, 0, len(arr))
		for _, item := range arr {
			item = strings.TrimSpace(item)
			if item != "" {
				out = append(out, item)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(arr))
		for _, item := range arr {
			s := strings.TrimSpace(fmt.Sprintf("%v", item))
			if s != "" && s != "<nil>" {
				out = append(out, s)
			}
		}
		return out
	case string:
		s := strings.TrimSpace(arr)
		if s == "" {
			return nil
		}
		return []string{s}
	default:
		s := strings.TrimSpace(fmt.Sprintf("%v", v))
		if s == "" || s == "<nil>" {
			return nil
		}
		return []string{s}
	}
}

func (p *webVulnGenericParser) parseWapiti(data string, trigger graph.Node, result *Result, now time.Time) bool {
	// wapiti JSON structure: {"vulnerabilities": {"category": [...]}}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(data), &raw); err != nil {
		return false
	}

	vulnsRaw, ok := raw["vulnerabilities"]
	if !ok {
		return false
	}

	var categories map[string][]wapitiFinding
	if err := json.Unmarshal(vulnsRaw, &categories); err != nil {
		return false
	}

	found := false
	idx := 0
	for category, findings := range categories {
		for _, f := range findings {
			if f.Info == "" && f.Path == "" {
				continue
			}
			found = true

			severity := p.wapitiSeverity(f.Level)
			evidence := map[string]any{
				"category":  category,
				"method":    f.Method,
				"path":      f.Path,
				"parameter": f.Parameter,
			}
			if f.HTTPCode > 0 {
				evidence["http_code"] = f.HTTPCode
			}
			if f.WapitiType != "" {
				evidence["wstg"] = f.WapitiType
			}

			findingID := fmt.Sprintf("wapiti-%s-%s-%d", category, hashKey(trigger.PrimaryKey), idx)
			result.Findings = append(result.Findings, graph.Finding{
				ID:         findingID,
				Type:       fmt.Sprintf("wapiti-%s", strings.ToLower(category)),
				Title:      f.Info,
				Severity:   severity,
				Confidence: "firm",
				Tool:       "wapiti",
				Evidence:   evidence,
				FirstSeen:  now,
				LastSeen:   now,
			})
			idx++
		}
	}
	return found
}

func (p *webVulnGenericParser) addDalfoxFinding(result *Result, rec dalfoxResult, trigger graph.Node, idx int, now time.Time, seen map[string]bool) {
	// Only count verified XSS findings.
	if rec.Type != "V" && rec.Type != "G" {
		return
	}

	severity := "medium"
	confidence := "tentative"
	if rec.Type == "V" {
		severity = "high"
		confidence = "confirmed"
	}
	if rec.Severity != "" {
		severity = strings.ToLower(rec.Severity)
	}

	findingID := fmt.Sprintf("dalfox-xss-%s-%d", hashKey(trigger.PrimaryKey+rec.Param), idx)
	if seen[findingID] {
		return
	}
	seen[findingID] = true

	evidence := map[string]any{
		"param":   rec.Param,
		"payload": rec.Payload,
		"poc":     rec.POC,
	}
	if rec.Evidence != "" {
		evidence["evidence"] = rec.Evidence
	}

	var cwes []string
	if rec.CWE != "" {
		cwes = []string{rec.CWE}
	}

	result.Findings = append(result.Findings, graph.Finding{
		ID:         findingID,
		Type:       "xss",
		Title:      fmt.Sprintf("XSS via %s parameter", rec.Param),
		Severity:   severity,
		Confidence: confidence,
		Tool:       "dalfox",
		CWE:        cwes,
		Evidence:   evidence,
		FirstSeen:  now,
		LastSeen:   now,
	})
}

func (p *webVulnGenericParser) addCorsyFinding(result *Result, rec corsyResult, trigger graph.Node, idx int, now time.Time, seen map[string]bool) {
	findingID := fmt.Sprintf("corsy-%s-%s-%d", rec.Type, hashKey(trigger.PrimaryKey), idx)
	if seen[findingID] {
		return
	}
	seen[findingID] = true

	severity := "medium"
	if rec.Severity != "" {
		severity = strings.ToLower(rec.Severity)
	}
	if rec.Credentials {
		// CORS with credentials is always high severity.
		severity = "high"
	}

	evidence := map[string]any{
		"origin":      rec.Origin,
		"credentials": rec.Credentials,
	}
	if rec.Description != "" {
		evidence["description"] = rec.Description
	}

	title := fmt.Sprintf("CORS misconfiguration: %s", rec.Type)
	if rec.Description != "" {
		title = rec.Description
	}

	result.Findings = append(result.Findings, graph.Finding{
		ID:         findingID,
		Type:       "cors-misconfiguration",
		Title:      title,
		Severity:   severity,
		Confidence: "firm",
		Tool:       "corsy",
		Evidence:   evidence,
		FirstSeen:  now,
		LastSeen:   now,
	})
}

func (p *webVulnGenericParser) wapitiSeverity(level string) string {
	switch strings.ToLower(level) {
	case "1":
		return "low"
	case "2":
		return "medium"
	case "3":
		return "high"
	case "4":
		return "critical"
	default:
		return "info"
	}
}
