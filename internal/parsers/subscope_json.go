package parsers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

// subscopeJSONParser handles the custom subscope tool's JSON output.
// subscope performs DNS enumeration on a Domain and outputs rich structured
// data including subdomains, IP addresses, and cloud provider tags.
type subscopeJSONParser struct{}

func init() {
	Register(&subscopeJSONParser{})
}

func (p *subscopeJSONParser) Name() string { return "subscope_json" }

// subscopeOutput represents the expected JSON output from subscope.
type subscopeOutput struct {
	Domain     string          `json:"domain"`
	Subdomains []subscopeSub   `json:"subdomains"`
	IPs        []subscopeIP    `json:"ips"`
	CloudTags  []subscopeCloud `json:"cloud_tags"`
	Timestamp  string          `json:"timestamp"`
}

type subscopeSub struct {
	FQDN       string   `json:"fqdn"`
	RecordType string   `json:"record_type"`
	Values     []string `json:"values"`
	Source     string   `json:"source"`
}

type subscopeIP struct {
	Address string `json:"address"`
	PTR     string `json:"ptr"`
}

type subscopeCloud struct {
	Provider string `json:"provider"` // aws, gcp, azure, cloudflare, etc.
	Service  string `json:"service"`  // s3, cloudfront, etc.
	Target   string `json:"target"`   // the domain/IP this tag applies to
}

func (p *subscopeJSONParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	// subscope writes progress text to stdout before the JSON object.
	// Read all output, find the first '{', and decode from there.
	raw, err := io.ReadAll(stdout)
	if err != nil {
		return Result{}, fmt.Errorf("read subscope output: %w", err)
	}

	idx := bytes.IndexByte(raw, '{')
	if idx < 0 {
		return Result{}, fmt.Errorf("subscope output contains no JSON object (got %d bytes of text)", len(raw))
	}
	raw = raw[idx:]

	var output subscopeOutput
	if err := json.Unmarshal(raw, &output); err != nil {
		return Result{}, fmt.Errorf("decode subscope JSON: %w", err)
	}

	var result Result
	seenSubs := make(map[string]bool)
	seenIPs := make(map[string]bool)

	// Process subdomains.
	for _, sub := range output.Subdomains {
		fqdn := strings.ToLower(strings.TrimSuffix(sub.FQDN, "."))
		if fqdn == "" || seenSubs[fqdn] {
			continue
		}
		seenSubs[fqdn] = true

		result.Nodes = append(result.Nodes, graph.Node{
			Type:       graph.NodeSubdomain,
			PrimaryKey: fqdn,
			Props: map[string]any{
				"fqdn":   fqdn,
				"status": "discovered",
				"source": sub.Source,
			},
		})

		// HAS edge from triggering domain.
		result.Edges = append(result.Edges, graph.Edge{
			Type:     graph.RelHAS,
			FromType: graph.NodeDomain,
			FromKey:  trigger.PrimaryKey,
			ToType:   graph.NodeSubdomain,
			ToKey:    fqdn,
		})

		// If we have resolution values, create RESOLVES_TO edges.
		for _, val := range sub.Values {
			val = strings.TrimSpace(val)
			if val == "" {
				continue
			}

			if sub.RecordType == "A" || sub.RecordType == "AAAA" {
				if !seenIPs[val] {
					seenIPs[val] = true
					result.Nodes = append(result.Nodes, graph.Node{
						Type:       graph.NodeIP,
						PrimaryKey: val,
						Props: map[string]any{
							"address": val,
						},
					})
				}
				result.Edges = append(result.Edges, graph.Edge{
					Type:     graph.RelRESOLVES_TO,
					FromType: graph.NodeSubdomain,
					FromKey:  fqdn,
					ToType:   graph.NodeIP,
					ToKey:    val,
					Props: map[string]any{
						"record_type": sub.RecordType,
					},
				})
			} else if sub.RecordType == "CNAME" {
				target := strings.ToLower(strings.TrimSuffix(val, "."))
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
		}
	}

	// Process standalone IPs.
	for _, ip := range output.IPs {
		if ip.Address == "" || seenIPs[ip.Address] {
			continue
		}
		seenIPs[ip.Address] = true

		props := map[string]any{
			"address": ip.Address,
		}
		if ip.PTR != "" {
			props["ptr"] = ip.PTR
		}

		result.Nodes = append(result.Nodes, graph.Node{
			Type:       graph.NodeIP,
			PrimaryKey: ip.Address,
			Props:      props,
		})
	}

	// Process cloud tags as findings on the relevant target.
	for _, tag := range output.CloudTags {
		if tag.Target == "" || tag.Provider == "" {
			continue
		}
		result.Findings = append(result.Findings, graph.Finding{
			ID:         fmt.Sprintf("cloud-%s-%s-%s", tag.Provider, tag.Service, tag.Target),
			Type:       "cloud-provider-detected",
			Title:      fmt.Sprintf("Cloud: %s/%s on %s", tag.Provider, tag.Service, tag.Target),
			Severity:   "info",
			Confidence: "confirmed",
			Tool:       "subscope",
			Evidence: map[string]any{
				"provider": tag.Provider,
				"service":  tag.Service,
				"target":   tag.Target,
			},
			FirstSeen: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
		})
	}

	return result, nil
}
