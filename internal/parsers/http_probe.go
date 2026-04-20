package parsers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	neturl "net/url"
	"strings"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

// httpProbeParser handles HTTP probing tools: httpx, webanalyze.
//
// Primary format: httpx JSON (-json), one object per line.
// Emits URL nodes, Technology nodes, and enriches Service nodes with
// TLS certificate, JARM fingerprint, CDN, headers, and other metadata.
type httpProbeParser struct{}

func init() {
	Register(&httpProbeParser{})
}

func (p *httpProbeParser) Name() string { return "http_probe" }

// httpxTLS represents TLS certificate data from httpx -tls-grab.
type httpxTLS struct {
	Host            string            `json:"host"`
	Port            string            `json:"port"`
	ProbeStatus     bool              `json:"probe_status"`
	TLSVersion      string            `json:"tls_version"`
	Cipher          string            `json:"cipher"`
	NotBefore       string            `json:"not_before"`
	NotAfter        string            `json:"not_after"`
	SubjectDN       string            `json:"subject_dn"`
	SubjectCN       string            `json:"subject_cn"`
	SubjectAN       []string          `json:"subject_an"` // SANs
	Serial          string            `json:"serial"`
	IssuerDN        string            `json:"issuer_dn"`
	IssuerCN        string            `json:"issuer_cn"`
	IssuerOrg       []string          `json:"issuer_org"`
	FingerprintHash map[string]string `json:"fingerprint_hash"`
	Wildcard        bool              `json:"wildcard_certificate"`
	SNI             string            `json:"sni"`
}

// httpxHash represents response body/header hashes.
type httpxHash struct {
	BodySHA256   string `json:"body_sha256"`
	HeaderSHA256 string `json:"header_sha256"`
}

// httpxRecord represents a single httpx JSON output line.
type httpxRecord struct {
	URL           string            `json:"url"`
	Input         string            `json:"input"`
	StatusCode    int               `json:"status_code"`
	ContentLength int               `json:"content_length"`
	ContentType   string            `json:"content_type"`
	Title         string            `json:"title"`
	Host          string            `json:"host"`
	Port          string            `json:"port"`
	Scheme        string            `json:"scheme"`
	Technologies  []string          `json:"tech"`
	WebServer     string            `json:"webserver"`
	ResponseTime  string            `json:"response_time"`
	Method        string            `json:"method"`
	FinalURL      string            `json:"final_url"`
	Failed        bool              `json:"failed"`
	Lines         int               `json:"lines"`
	Words         int               `json:"words"`
	A             []string          `json:"a"`     // resolved A records
	AAAA          []string          `json:"aaaa"`  // resolved AAAA records
	CNAME         []string          `json:"cname"` // CNAME records
	CDNName       string            `json:"cdn_name"`
	CDNType       string            `json:"cdn_type"`
	CDN           bool              `json:"cdn"`
	TLS           *httpxTLS         `json:"tls"`
	JARMHash      string            `json:"jarm_hash"`
	FaviconMMH3   string            `json:"favicon"`
	Hash          *httpxHash        `json:"hash"`
	Header        map[string]string `json:"header"` // response headers from -irh
	HostIP        string            `json:"host_ip"`
}

func (p *httpProbeParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var result Result
	seenURLs := make(map[string]bool)
	seenTech := make(map[string]bool)

	scanner := bufio.NewScanner(stdout)
	// httpx can produce long lines; increase buffer.
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var rec httpxRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}

		if rec.Failed || rec.URL == "" {
			continue
		}

		p.processRecord(&result, rec, trigger, seenURLs, seenTech)
	}

	return result, scanner.Err()
}

func (p *httpProbeParser) processRecord(result *Result, rec httpxRecord, trigger graph.Node, seenURLs, seenTech map[string]bool) {
	url := rec.URL
	if seenURLs[url] {
		return
	}
	seenURLs[url] = true

	// Build URL node with all httpx metadata.
	props := map[string]any{
		"url":            url,
		"status_code":    rec.StatusCode,
		"content_length": rec.ContentLength,
		"content_type":   rec.ContentType,
		"title":          rec.Title,
		"scheme":         rec.Scheme,
		"webserver":      rec.WebServer,
		"server":         rec.WebServer,
	}
	if rec.Host != "" {
		props["host"] = rec.Host
	}
	if parsed, err := neturl.Parse(url); err == nil {
		if parsed.Hostname() != "" {
			props["host"] = parsed.Hostname()
		}
		path := parsed.EscapedPath()
		if path == "" {
			path = "/"
		}
		props["path"] = path
	}
	if rec.FinalURL != "" && rec.FinalURL != url {
		props["final_url"] = rec.FinalURL
		props["has_redirects"] = true
	}
	if rec.CDNName != "" {
		props["cdn_name"] = rec.CDNName
		props["cdn_type"] = rec.CDNType
	}
	if rec.CDN {
		props["cdn"] = true
	}
	if rec.WebServer != "" {
		props["server"] = rec.WebServer
	}
	if rec.Lines > 0 {
		props["response_lines"] = rec.Lines
	}
	if rec.Words > 0 {
		props["response_words"] = rec.Words
	}
	// Response hashes.
	if rec.Hash != nil {
		if rec.Hash.BodySHA256 != "" {
			props["body_sha256"] = rec.Hash.BodySHA256
		}
		if rec.Hash.HeaderSHA256 != "" {
			props["header_sha256"] = rec.Hash.HeaderSHA256
		}
	}
	// Favicon hash.
	if rec.FaviconMMH3 != "" {
		props["favicon_mmh3"] = rec.FaviconMMH3
	}
	// JARM fingerprint on URL node.
	if rec.JARMHash != "" {
		props["jarm"] = rec.JARMHash
	}

	result.Nodes = append(result.Nodes, graph.Node{
		Type:       graph.NodeURL,
		PrimaryKey: url,
		Props:      props,
	})

	// Enrich the related Service node with TLS, JARM, CDN, and header data.
	triggerFQDN, _ := trigger.Props["fqdn"].(string)
	if triggerFQDN == "" {
		triggerFQDN = rec.Host
	}
	if rec.Port != "" && triggerFQDN != "" {
		var port int
		if _, err := fmt.Sscanf(rec.Port, "%d", &port); err == nil && port > 0 {
			fqdnPort := fmt.Sprintf("%s:%d", triggerFQDN, port)
			svcProps := map[string]any{
				"fqdn_port": fqdnPort,
				"fqdn":      triggerFQDN,
				"port":      port,
			}
			if rec.WebServer != "" {
				svcProps["server"] = rec.WebServer
			}
			// Store first resolved IP as metadata.
			for _, ip := range rec.A {
				ip = strings.TrimSpace(ip)
				if ip != "" {
					svcProps["ip"] = ip
					break
				}
			}
			// CDN info on Service.
			if rec.CDNName != "" {
				svcProps["cdn_name"] = rec.CDNName
				svcProps["cdn_type"] = rec.CDNType
			}
			if rec.CDN {
				svcProps["cdn"] = true
			}
			// JARM fingerprint.
			if rec.JARMHash != "" {
				svcProps["jarm"] = rec.JARMHash
			}
			// TLS certificate data.
			if rec.TLS != nil && rec.TLS.ProbeStatus {
				svcProps["tls"] = true
				svcProps["tls_version"] = rec.TLS.TLSVersion
				svcProps["tls_cipher"] = rec.TLS.Cipher
				svcProps["tls_subject_cn"] = rec.TLS.SubjectCN
				svcProps["tls_issuer_cn"] = rec.TLS.IssuerCN
				if len(rec.TLS.IssuerOrg) > 0 {
					svcProps["tls_issuer_org"] = strings.Join(rec.TLS.IssuerOrg, ", ")
				}
				svcProps["tls_not_before"] = rec.TLS.NotBefore
				svcProps["tls_not_after"] = rec.TLS.NotAfter
				svcProps["tls_serial"] = rec.TLS.Serial
				if len(rec.TLS.SubjectAN) > 0 {
					svcProps["tls_sans"] = strings.Join(rec.TLS.SubjectAN, ",")
				}
				if rec.TLS.Wildcard {
					svcProps["tls_wildcard"] = true
				}
				if sha256, ok := rec.TLS.FingerprintHash["sha256"]; ok && sha256 != "" {
					svcProps["tls_fingerprint_sha256"] = sha256
				}
			}
			result.Nodes = append(result.Nodes, graph.Node{
				Type:       graph.NodeService,
				PrimaryKey: fqdnPort,
				Props:      svcProps,
			})
		}
	}

	// Enrich the triggering Subdomain node with CNAME and CDN info.
	if trigger.Type == graph.NodeSubdomain {
		subProps := map[string]any{}
		if len(rec.CNAME) > 0 {
			subProps["cnames"] = strings.Join(rec.CNAME, ",")
		}
		if rec.CDNName != "" {
			subProps["cdn_name"] = rec.CDNName
			subProps["cdn_type"] = rec.CDNType
		}
		if rec.CDN {
			subProps["cdn"] = true
		}
		if len(subProps) > 0 {
			subProps["fqdn"] = trigger.PrimaryKey
			result.Nodes = append(result.Nodes, graph.Node{
				Type:       graph.NodeSubdomain,
				PrimaryKey: trigger.PrimaryKey,
				Props:      subProps,
			})
		}
	}

	// SERVES edge from triggering Subdomain to URL.
	if trigger.Type == graph.NodeSubdomain {
		edgeProps := map[string]any{
			"scheme": rec.Scheme,
		}
		if rec.Port != "" {
			edgeProps["port"] = rec.Port
		}
		// Carry resolved IPs for DNS-first rule.
		if len(rec.A) > 0 {
			edgeProps["resolved_ip"] = rec.A[0]
		}

		result.Edges = append(result.Edges, graph.Edge{
			Type:     graph.RelSERVES,
			FromType: graph.NodeSubdomain,
			FromKey:  trigger.PrimaryKey,
			ToType:   graph.NodeURL,
			ToKey:    url,
			Props:    edgeProps,
		})
	}

	// Technology nodes.
	for _, tech := range rec.Technologies {
		tech = strings.TrimSpace(tech)
		if tech == "" {
			continue
		}

		techKey := technologyID(tech, "")
		if seenTech[techKey] {
			// Still create the RUNS edge even if node already seen.
		} else {
			seenTech[techKey] = true
			result.Nodes = append(result.Nodes, graph.Node{
				Type:       graph.NodeTechnology,
				PrimaryKey: techKey,
				Props: map[string]any{
					"tech_id": techKey,
					"name":    tech,
					"version": "", // httpx doesn't provide version granularity
				},
			})
		}

		result.Edges = append(result.Edges, graph.Edge{
			Type:     graph.RelRUNS,
			FromType: graph.NodeURL,
			FromKey:  url,
			ToType:   graph.NodeTechnology,
			ToKey:    techKey,
			Props: map[string]any{
				"confidence": "tentative",
			},
		})
	}
}
