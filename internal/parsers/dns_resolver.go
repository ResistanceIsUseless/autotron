package parsers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

// dnsResolverParser handles tools that resolve hostnames to IPs and return
// structured DNS data: dnsx, puredns, shuffledns, massdns.
//
// Primary expected format: dnsx JSON (-json flag), one object per line.
// Fallback: plain text lines "hostname A ip" (massdns simple output).
type dnsResolverParser struct{}

func init() {
	Register(&dnsResolverParser{})
}

func (p *dnsResolverParser) Name() string { return "dns_resolver" }

// dnsxRecord represents a single dnsx JSON output line.
type dnsxRecord struct {
	Host       string   `json:"host"`
	A          []string `json:"a"`
	AAAA       []string `json:"aaaa"`
	CNAME      []string `json:"cname"`
	StatusCode string   `json:"status_code"`
	Timestamp  string   `json:"timestamp"`
}

func (p *dnsResolverParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var result Result
	seenSubs := make(map[string]bool)
	seenIPs := make(map[string]bool)

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Try JSON first (dnsx -json output).
		if strings.HasPrefix(line, "{") {
			var rec dnsxRecord
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				continue // skip malformed lines
			}
			p.processDNSXRecord(&result, rec, trigger, seenSubs, seenIPs)
			continue
		}

		// Fallback: plain text "hostname A ip" or just "hostname ip".
		p.processPlainLine(&result, line, trigger, seenSubs, seenIPs)
	}

	return result, scanner.Err()
}

func (p *dnsResolverParser) processDNSXRecord(result *Result, rec dnsxRecord, trigger graph.Node, seenSubs, seenIPs map[string]bool) {
	fqdn := strings.ToLower(strings.TrimSuffix(rec.Host, "."))
	if fqdn == "" {
		return
	}

	// Upsert subdomain with resolved status.
	if !seenSubs[fqdn] {
		seenSubs[fqdn] = true
		status := "resolved"
		if rec.StatusCode == "NXDOMAIN" || rec.StatusCode == "SERVFAIL" {
			status = "nxdomain"
		}
		result.Nodes = append(result.Nodes, graph.Node{
			Type:       graph.NodeSubdomain,
			PrimaryKey: fqdn,
			Props: map[string]any{
				"fqdn":       fqdn,
				"status":     status,
				"dns_status": rec.StatusCode,
			},
		})
	}

	// A records -> IP nodes + RESOLVES_TO edges.
	for _, addr := range rec.A {
		p.addIPEdge(result, fqdn, addr, "A", seenIPs)
	}

	// AAAA records.
	for _, addr := range rec.AAAA {
		p.addIPEdge(result, fqdn, addr, "AAAA", seenIPs)
	}

	// CNAME records -> Subdomain nodes + CNAME edges.
	for _, target := range rec.CNAME {
		target = strings.ToLower(strings.TrimSuffix(target, "."))
		if target == "" {
			continue
		}
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

func (p *dnsResolverParser) addIPEdge(result *Result, fqdn, addr, recordType string, seenIPs map[string]bool) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return
	}
	if !seenIPs[addr] {
		seenIPs[addr] = true
		result.Nodes = append(result.Nodes, graph.Node{
			Type:       graph.NodeIP,
			PrimaryKey: addr,
			Props: map[string]any{
				"address": addr,
			},
		})
	}
	result.Edges = append(result.Edges, graph.Edge{
		Type:     graph.RelRESOLVES_TO,
		FromType: graph.NodeSubdomain,
		FromKey:  fqdn,
		ToType:   graph.NodeIP,
		ToKey:    addr,
		Props: map[string]any{
			"record_type": recordType,
		},
	})
}

func (p *dnsResolverParser) processPlainLine(result *Result, line string, trigger graph.Node, seenSubs, seenIPs map[string]bool) {
	// Formats: "hostname A ip", "hostname AAAA ip", "hostname ip"
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return
	}

	fqdn := strings.ToLower(strings.TrimSuffix(fields[0], "."))
	var addr, recType string

	if len(fields) >= 3 {
		recType = strings.ToUpper(fields[1])
		addr = fields[2]
	} else {
		addr = fields[1]
		// Infer record type from address.
		if ip := net.ParseIP(addr); ip != nil {
			if ip.To4() != nil {
				recType = "A"
			} else {
				recType = "AAAA"
			}
		} else {
			return // not a recognizable format
		}
	}

	if fqdn == "" || addr == "" {
		return
	}

	if !seenSubs[fqdn] {
		seenSubs[fqdn] = true
		result.Nodes = append(result.Nodes, graph.Node{
			Type:       graph.NodeSubdomain,
			PrimaryKey: fqdn,
			Props: map[string]any{
				"fqdn":   fqdn,
				"status": "resolved",
			},
		})
	}

	if recType == "CNAME" {
		target := strings.ToLower(strings.TrimSuffix(addr, "."))
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
	} else {
		_ = fmt.Sprintf("") // avoid unused import
		p.addIPEdge(result, fqdn, addr, recType, seenIPs)
	}
}
