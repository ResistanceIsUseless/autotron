package parsers

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

// tlsAuditParser handles TLS certificate and cipher audit tools:
// tlsx, testssl.sh, sslyze.
//
// Primary format: tlsx JSON (-json), one object per line.
// Extracts certificates, SANs (which cycle back into Subdomain nodes),
// and cipher/protocol issues as findings.
type tlsAuditParser struct{}

func init() {
	Register(&tlsAuditParser{})
}

func (p *tlsAuditParser) Name() string { return "tls_audit" }

// tlsxRecord represents a single tlsx JSON output line.
type tlsxRecord struct {
	Host            string   `json:"host"`
	IP              string   `json:"ip"`
	Port            string   `json:"port"`
	TLSVersion      string   `json:"tls_version"`
	CipherSuite     string   `json:"cipher"`
	SubjectCN       string   `json:"subject_cn"`
	SubjectOrg      string   `json:"subject_org"`
	IssuerCN        string   `json:"issuer_cn"`
	IssuerOrg       string   `json:"issuer_org"`
	SANs            []string `json:"subject_an"`
	Serial          string   `json:"serial"`
	FingerprintHash string   `json:"fingerprint_hash"`
	NotBefore       string   `json:"not_before"`
	NotAfter        string   `json:"not_after"`
	Expired         bool     `json:"expired"`
	SelfSigned      bool     `json:"self_signed"`
	WildcardCert    bool     `json:"wildcard_cert"`
}

func (p *tlsAuditParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var result Result
	seenCerts := make(map[string]bool)
	seenSubs := make(map[string]bool)

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var rec tlsxRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}

		p.processRecord(&result, rec, trigger, seenCerts, seenSubs)
	}

	return result, scanner.Err()
}

func (p *tlsAuditParser) processRecord(result *Result, rec tlsxRecord, trigger graph.Node, seenCerts, seenSubs map[string]bool) {
	// Build certificate hash — use fingerprint from tool or derive one.
	certHash := rec.FingerprintHash
	if certHash == "" {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s", rec.Serial, rec.SubjectCN, rec.NotBefore)))
		certHash = fmt.Sprintf("%x", h)
	}

	// Upsert Certificate node.
	if !seenCerts[certHash] {
		seenCerts[certHash] = true

		certProps := map[string]any{
			"sha256":        certHash,
			"subject_cn":    rec.SubjectCN,
			"subject_org":   rec.SubjectOrg,
			"issuer_cn":     rec.IssuerCN,
			"issuer_org":    rec.IssuerOrg,
			"serial":        rec.Serial,
			"not_before":    rec.NotBefore,
			"not_after":     rec.NotAfter,
			"expired":       rec.Expired,
			"self_signed":   rec.SelfSigned,
			"wildcard_cert": rec.WildcardCert,
			"tls_version":   rec.TLSVersion,
		}
		if len(rec.SANs) > 0 {
			certProps["sans"] = rec.SANs
		}

		result.Nodes = append(result.Nodes, graph.Node{
			Type:       graph.NodeCertificate,
			PrimaryKey: certHash,
			Props:      certProps,
		})

		// PRESENTS edge from Service to Certificate.
		if trigger.Type == graph.NodeService {
			result.Edges = append(result.Edges, graph.Edge{
				Type:     graph.RelPRESENTS,
				FromType: graph.NodeService,
				FromKey:  trigger.PrimaryKey,
				ToType:   graph.NodeCertificate,
				ToKey:    certHash,
			})
		}
	}

	// SANs feed back into Subdomain nodes — this is where the TLS cycle lives.
	for _, san := range rec.SANs {
		san = strings.ToLower(strings.TrimSuffix(san, "."))
		// Skip wildcards and IPs.
		if strings.HasPrefix(san, "*.") {
			san = san[2:] // strip wildcard, keep base domain
		}
		if san == "" || strings.Contains(san, "*") {
			continue
		}
		if seenSubs[san] {
			continue
		}
		seenSubs[san] = true

		result.Nodes = append(result.Nodes, graph.Node{
			Type:       graph.NodeSubdomain,
			PrimaryKey: san,
			Props: map[string]any{
				"fqdn":   san,
				"status": "discovered",
				"source": "tls-san",
			},
		})
	}

	// Generate findings for cert/protocol issues.
	p.generateFindings(result, rec, trigger)
}

func (p *tlsAuditParser) generateFindings(result *Result, rec tlsxRecord, trigger graph.Node) {
	now := time.Now().UTC()
	target := fmt.Sprintf("%s:%s", rec.Host, rec.Port)

	// Expired certificate.
	if rec.Expired {
		result.Findings = append(result.Findings, graph.Finding{
			ID:         fmt.Sprintf("tls-expired-%s", target),
			Type:       "tls-expired-certificate",
			Title:      fmt.Sprintf("Expired TLS certificate on %s", target),
			Severity:   "high",
			Confidence: "confirmed",
			Tool:       "tlsx",
			Evidence: map[string]any{
				"not_after":  rec.NotAfter,
				"subject_cn": rec.SubjectCN,
			},
			FirstSeen: now, LastSeen: now,
		})
	}

	// Self-signed certificate.
	if rec.SelfSigned {
		result.Findings = append(result.Findings, graph.Finding{
			ID:         fmt.Sprintf("tls-selfsigned-%s", target),
			Type:       "tls-self-signed",
			Title:      fmt.Sprintf("Self-signed certificate on %s", target),
			Severity:   "medium",
			Confidence: "confirmed",
			Tool:       "tlsx",
			Evidence: map[string]any{
				"issuer_cn":  rec.IssuerCN,
				"subject_cn": rec.SubjectCN,
			},
			FirstSeen: now, LastSeen: now,
		})
	}

	// Weak TLS version.
	weakVersions := map[string]string{
		"ssl2":   "critical",
		"ssl3":   "critical",
		"tls1.0": "high",
		"tls10":  "high",
		"tls1.1": "medium",
		"tls11":  "medium",
	}
	normalized := strings.ToLower(strings.ReplaceAll(rec.TLSVersion, " ", ""))
	if sev, weak := weakVersions[normalized]; weak {
		result.Findings = append(result.Findings, graph.Finding{
			ID:         fmt.Sprintf("tls-weak-version-%s-%s", normalized, target),
			Type:       "tls-weak-version",
			Title:      fmt.Sprintf("Weak TLS version %s on %s", rec.TLSVersion, target),
			Severity:   sev,
			Confidence: "confirmed",
			Tool:       "tlsx",
			Evidence: map[string]any{
				"tls_version": rec.TLSVersion,
			},
			FirstSeen: now, LastSeen: now,
		})
	}

	// Weak cipher suite.
	weakCiphers := []string{"rc4", "des", "null", "export", "anon"}
	cipherLower := strings.ToLower(rec.CipherSuite)
	for _, w := range weakCiphers {
		if strings.Contains(cipherLower, w) {
			result.Findings = append(result.Findings, graph.Finding{
				ID:         fmt.Sprintf("tls-weak-cipher-%s-%s", w, target),
				Type:       "tls-weak-cipher",
				Title:      fmt.Sprintf("Weak cipher %s on %s", rec.CipherSuite, target),
				Severity:   "medium",
				Confidence: "confirmed",
				Tool:       "tlsx",
				Evidence: map[string]any{
					"cipher_suite": rec.CipherSuite,
				},
				FirstSeen: now, LastSeen: now,
			})
			break // one finding per cipher
		}
	}
}
