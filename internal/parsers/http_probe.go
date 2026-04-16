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
// Emits URL nodes and Technology nodes.
type httpProbeParser struct{}

func init() {
	Register(&httpProbeParser{})
}

func (p *httpProbeParser) Name() string { return "http_probe" }

// httpxRecord represents a single httpx JSON output line.
type httpxRecord struct {
	URL           string   `json:"url"`
	Input         string   `json:"input"`
	StatusCode    int      `json:"status_code"`
	ContentLength int      `json:"content_length"`
	ContentType   string   `json:"content_type"`
	Title         string   `json:"title"`
	Host          string   `json:"host"`
	Port          string   `json:"port"`
	Scheme        string   `json:"scheme"`
	Technologies  []string `json:"tech"`
	WebServer     string   `json:"webserver"`
	ResponseTime  string   `json:"response_time"`
	Method        string   `json:"method"`
	FinalURL      string   `json:"final_url"`
	Failed        bool     `json:"failed"`
	Lines         int      `json:"lines"`
	Words         int      `json:"words"`
	A             []string `json:"a"` // resolved IPs
	CDNName       string   `json:"cdn_name"`
	CDNType       string   `json:"cdn_type"`
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
	if rec.WebServer != "" {
		props["server"] = rec.WebServer
	}
	if rec.Lines > 0 {
		props["response_lines"] = rec.Lines
	}
	if rec.Words > 0 {
		props["response_words"] = rec.Words
	}

	result.Nodes = append(result.Nodes, graph.Node{
		Type:       graph.NodeURL,
		PrimaryKey: url,
		Props:      props,
	})

	// Propagate HTTP server header to related Service nodes when possible.
	// This improves service-level context in UI for HTTP/HTTPS services.
	if rec.WebServer != "" && rec.Port != "" && len(rec.A) > 0 {
		var port int
		if _, err := fmt.Sscanf(rec.Port, "%d", &port); err == nil && port > 0 {
			for _, ip := range rec.A {
				ip = strings.TrimSpace(ip)
				if ip == "" {
					continue
				}
				ipPort := fmt.Sprintf("%s:%d", ip, port)
				result.Nodes = append(result.Nodes, graph.Node{
					Type:       graph.NodeService,
					PrimaryKey: ipPort,
					Props: map[string]any{
						"ip_port": ipPort,
						"ip":      ip,
						"port":    port,
						"server":  rec.WebServer,
					},
				})
			}
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
