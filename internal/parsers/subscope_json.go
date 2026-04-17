package parsers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

// subscopeJSONParser handles the custom subscope tool's JSON output.
// subscope performs DNS enumeration on a Domain and outputs rich structured
// data including resolved/discovered domains with DNS records and cloud metadata.
type subscopeJSONParser struct{}

func init() {
	Register(&subscopeJSONParser{})
}

func (p *subscopeJSONParser) Name() string { return "subscope_json" }

// subscopeOutput represents the actual JSON output from subscope.
type subscopeOutput struct {
	Metadata          subscopeMetadata `json:"metadata"`
	Statistics        json.RawMessage  `json:"statistics"`
	ResolvedDomains   []subscopeDomain `json:"resolved_domains"`
	DiscoveredDomains []subscopeDomain `json:"discovered_domains"`
}

type subscopeMetadata struct {
	Version   string `json:"version"`
	Timestamp string `json:"timestamp"`
	Target    string `json:"target"`
}

type subscopeDomain struct {
	Domain     string            `json:"domain"`
	Status     string            `json:"status"`      // "resolved" or "failed"
	DNSRecords map[string]string `json:"dns_records"` // A, A_ALL, CNAME, CLOUD_SERVICE, etc.
	Source     string            `json:"source"`
	Timestamp  string            `json:"timestamp"`
}

func (p *subscopeJSONParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	raw, err := io.ReadAll(stdout)
	if err != nil {
		return Result{}, fmt.Errorf("read subscope output: %w", err)
	}

	if len(raw) == 0 {
		return Result{}, fmt.Errorf("subscope produced no output")
	}

	var output subscopeOutput
	if err := json.Unmarshal(raw, &output); err != nil {
		return Result{}, fmt.Errorf("decode subscope JSON: %w", err)
	}

	var result Result
	seenSubs := make(map[string]bool)
	seenIPs := make(map[string]bool)
	now := time.Now().UTC()

	// Process both resolved and discovered domains.
	allDomains := append(output.ResolvedDomains, output.DiscoveredDomains...)

	for _, d := range allDomains {
		fqdn := strings.ToLower(strings.TrimSuffix(d.Domain, "."))
		if fqdn == "" || seenSubs[fqdn] {
			continue
		}
		seenSubs[fqdn] = true

		status := "discovered"
		if d.Status == "resolved" {
			status = "resolved"
		}

		subProps := map[string]any{
			"fqdn":   fqdn,
			"status": status,
			"source": d.Source,
		}

		// Extract IPs from dns_records and store as metadata on Subdomain.
		var ips []string
		if aAll, ok := d.DNSRecords["A_ALL"]; ok && aAll != "" {
			ips = strings.Split(aAll, ",")
		} else if a, ok := d.DNSRecords["A"]; ok && a != "" {
			ips = []string{a}
		}

		if len(ips) > 0 {
			subProps["ips"] = strings.Join(ips, ",")
		}

		if cname, ok := d.DNSRecords["CNAME"]; ok && cname != "" {
			subProps["cname"] = strings.ToLower(strings.TrimSuffix(cname, "."))
		}

		if cloudSvc, ok := d.DNSRecords["CLOUD_SERVICE"]; ok && cloudSvc != "" {
			subProps["cloud_service"] = cloudSvc
		}
		if cloudDNS, ok := d.DNSRecords["CLOUD_DNS"]; ok && cloudDNS != "" {
			subProps["cloud_dns"] = cloudDNS
		}

		result.Nodes = append(result.Nodes, graph.Node{
			Type:       graph.NodeSubdomain,
			PrimaryKey: fqdn,
			Props:      subProps,
		})

		// HAS edge from triggering domain.
		result.Edges = append(result.Edges, graph.Edge{
			Type:     graph.RelHAS,
			FromType: graph.NodeDomain,
			FromKey:  trigger.PrimaryKey,
			ToType:   graph.NodeSubdomain,
			ToKey:    fqdn,
		})

		// Create IP nodes and RESOLVES_TO edges for public IPs.
		for _, ipStr := range ips {
			ipStr = strings.TrimSpace(ipStr)
			if ipStr == "" {
				continue
			}
			ip := net.ParseIP(ipStr)
			if ip == nil || ip.IsPrivate() || ip.IsLoopback() {
				continue
			}
			if !seenIPs[ipStr] {
				seenIPs[ipStr] = true
				result.Nodes = append(result.Nodes, graph.Node{
					Type:       graph.NodeIP,
					PrimaryKey: ipStr,
					Props: map[string]any{
						"address": ipStr,
					},
				})
			}
			result.Edges = append(result.Edges, graph.Edge{
				Type:     graph.RelRESOLVES_TO,
				FromType: graph.NodeSubdomain,
				FromKey:  fqdn,
				ToType:   graph.NodeIP,
				ToKey:    ipStr,
				Props: map[string]any{
					"record_type": "A",
				},
			})
		}

		// CNAME edge.
		if cname, ok := d.DNSRecords["CNAME"]; ok && cname != "" {
			target := strings.ToLower(strings.TrimSuffix(cname, "."))
			if !seenSubs[target] {
				seenSubs[target] = true
				result.Nodes = append(result.Nodes, graph.Node{
					Type:       graph.NodeSubdomain,
					PrimaryKey: target,
					Props: map[string]any{
						"fqdn":   target,
						"status": "discovered",
					},
				})
			}
			result.Edges = append(result.Edges, graph.Edge{
				Type:     graph.RelCNAME,
				FromType: graph.NodeSubdomain,
				FromKey:  fqdn,
				ToType:   graph.NodeSubdomain,
				ToKey:    target,
			})
		}

		// Cloud service finding.
		if cloudSvc, ok := d.DNSRecords["CLOUD_SERVICE"]; ok && cloudSvc != "" {
			result.Findings = append(result.Findings, graph.Finding{
				ID:         fmt.Sprintf("cloud-%s-%s", strings.ToLower(cloudSvc), fqdn),
				Type:       "cloud-provider-detected",
				Title:      fmt.Sprintf("Cloud: %s on %s", cloudSvc, fqdn),
				Severity:   "info",
				Confidence: "confirmed",
				Tool:       "subscope",
				Evidence: map[string]any{
					"provider": cloudSvc,
					"target":   fqdn,
				},
				FirstSeen: now,
				LastSeen:  now,
			})
		}
	}

	return result, nil
}
