package graph

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// CorrelateFinding normalizes a finding into a canonical key that can be used
// to merge duplicate observations from different tools.
func CorrelateFinding(f Finding, parentType NodeType, parentKey string) (canonicalType, canonicalKey string) {
	canonicalType = normalizeFindingType(f)
	normalizedParent := strings.ToLower(strings.TrimSpace(parentKey))

	if canonicalParent, ok := correlateParentFromEvidence(f); ok {
		normalizedParent = canonicalParent
	}

	signal := normalizeSignal(f, canonicalType)
	canonicalKey = fmt.Sprintf("%s|%s|%s|%s", canonicalType, strings.ToLower(string(parentType)), normalizedParent, signal)
	return canonicalType, canonicalKey
}

func canonicalFindingID(canonicalKey, fallbackID string) string {
	trimmed := strings.TrimSpace(canonicalKey)
	if trimmed == "" {
		return fallbackID
	}
	sum := sha256.Sum256([]byte(trimmed))
	return fmt.Sprintf("corr-%x", sum[:12])
}

func normalizeFindingType(f Finding) string {
	t := strings.ToLower(strings.TrimSpace(f.Type))
	if t == "" {
		t = "observation"
	}

	if strings.HasPrefix(t, "cve-") {
		return "cve"
	}
	if strings.Contains(t, "tls-weak-cipher") {
		return "tls-weak-cipher"
	}
	if strings.Contains(t, "tls-weak-version") {
		return "tls-weak-version"
	}
	if strings.Contains(t, "subdomain-takeover") || strings.Contains(t, "takeover") {
		return "subdomain-takeover"
	}
	if strings.Contains(t, "open-redirect") {
		return "open-redirect"
	}
	if strings.Contains(t, "ssrf") {
		return "ssrf"
	}
	if strings.Contains(t, "secret-") {
		return "secret-exposure"
	}

	return t
}

func correlateParentFromEvidence(f Finding) (string, bool) {
	if f.Evidence == nil {
		return "", false
	}

	for _, key := range []string{"matched_at", "url", "host", "ip", "target", "service"} {
		if v, ok := f.Evidence[key]; ok {
			s := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", v)))
			if s != "" {
				return s, true
			}
		}
	}

	return "", false
}

func normalizeSignal(f Finding, canonicalType string) string {
	if canonicalType == "cve" {
		if len(f.CVE) > 0 {
			return strings.ToLower(strings.TrimSpace(f.CVE[0]))
		}
		if f.Evidence != nil {
			if tid, ok := f.Evidence["template_id"]; ok {
				return strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", tid)))
			}
		}
	}

	if f.Evidence != nil {
		if script, ok := f.Evidence["script_id"]; ok {
			return strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", script)))
		}
		if det, ok := f.Evidence["detector"]; ok {
			return strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", det)))
		}
		if param, ok := f.Evidence["param"]; ok {
			return strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", param)))
		}
	}

	if strings.TrimSpace(f.Title) != "" {
		return strings.ToLower(strings.TrimSpace(f.Title))
	}

	return canonicalType
}
