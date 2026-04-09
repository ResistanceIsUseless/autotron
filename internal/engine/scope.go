// Package engine implements the ASM pipeline dispatcher. It manages the
// enrichment loop: query pending nodes, dispatch to parsers via runners,
// persist results, and repeat until convergence or budget exhaustion.
package engine

import (
	"net"
	"strings"

	"github.com/resistanceisuseless/autotron/internal/config"
	"github.com/resistanceisuseless/autotron/internal/graph"
)

// ScopeValidator checks whether a node is in-scope for further enrichment.
// Out-of-scope nodes are recorded as findings but do not trigger enrichers.
type ScopeValidator struct {
	domains      []string // suffix match list
	cidrs        []*net.IPNet
	asns         map[int]bool
	ipDirectHTTP bool
}

// NewScopeValidator creates a validator from the loaded config.
func NewScopeValidator(cfg *config.Config) *ScopeValidator {
	asns := make(map[int]bool, len(cfg.Scope.ASNs))
	for _, asn := range cfg.Scope.ASNs {
		asns[asn] = true
	}
	return &ScopeValidator{
		domains:      cfg.Scope.Domains,
		cidrs:        cfg.ParsedCIDRs(),
		asns:         asns,
		ipDirectHTTP: cfg.Scope.IPDirect,
	}
}

// IsInScope checks whether a node should be considered in-scope based on
// its own properties (domain suffix match, CIDR match). For IP nodes with
// no matching CIDR, use IsInScopeWithParent to allow inheritance from
// an in-scope trigger node.
//
// Rules by node type:
//   - Domain/Subdomain: FQDN must be a suffix match against scope domains
//   - IP: must fall within a scope CIDR (use IsInScopeWithParent for inheritance)
//   - All others: inherit scope from their parent (checked by the engine)
func (sv *ScopeValidator) IsInScope(node graph.Node) bool {
	return sv.IsInScopeWithParent(node, false)
}

// IsInScopeWithParent checks scope with an additional inheritance rule:
// IP nodes that don't match any configured CIDR can inherit in-scope status
// from their parent (trigger) node. This handles the common ASM case where
// IPs are discovered by resolving in-scope subdomains and no CIDRs are
// configured upfront.
//
// The parentInScope parameter reflects the in_scope status of the node that
// triggered the enricher which produced this child node.
func (sv *ScopeValidator) IsInScopeWithParent(node graph.Node, parentInScope bool) bool {
	switch node.Type {
	case graph.NodeDomain, graph.NodeSubdomain:
		return sv.domainInScope(node)
	case graph.NodeIP:
		// First check explicit CIDR match.
		if sv.ipInScope(node) {
			return true
		}
		// If no CIDRs matched, inherit from the in-scope parent that
		// caused this IP to be discovered (e.g. an in-scope subdomain
		// resolved via dnsx).
		return parentInScope
	default:
		// Other node types (Service, URL, etc.) inherit scope from parent
		// context. The engine passes this through props or the parent flag.
		if parentInScope {
			return true
		}
		if v, ok := node.Props["in_scope"]; ok {
			if b, ok := v.(bool); ok {
				return b
			}
		}
		return false
	}
}

// domainInScope checks if a domain/subdomain FQDN matches any scope domain
// via suffix matching.
func (sv *ScopeValidator) domainInScope(node graph.Node) bool {
	fqdn, _ := node.Props["fqdn"].(string)
	if fqdn == "" {
		return false
	}
	fqdn = strings.ToLower(strings.TrimSuffix(fqdn, "."))

	for _, domain := range sv.domains {
		domain = strings.ToLower(strings.TrimSuffix(domain, "."))
		if fqdn == domain || strings.HasSuffix(fqdn, "."+domain) {
			return true
		}
	}
	return false
}

// ipInScope checks if an IP address falls within any scope CIDR.
func (sv *ScopeValidator) ipInScope(node graph.Node) bool {
	addr, _ := node.Props["address"].(string)
	if addr == "" {
		return false
	}

	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}

	for _, cidr := range sv.cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// ASNInScope checks if an ASN number is in scope.
func (sv *ScopeValidator) ASNInScope(asn int) bool {
	return sv.asns[asn]
}

// AllowIPDirectHTTP returns whether HTTP probing of bare IPs is permitted.
func (sv *ScopeValidator) AllowIPDirectHTTP() bool {
	return sv.ipDirectHTTP
}
