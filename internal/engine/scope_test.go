package engine

import (
	"testing"

	"github.com/resistanceisuseless/autotron/internal/config"
	"github.com/resistanceisuseless/autotron/internal/graph"
)

func TestShouldEnrichURLHostInScope(t *testing.T) {
	sv := NewScopeValidator(&config.Config{Scope: config.ScopeConfig{Domains: []string{"example.com"}}})

	node := graph.Node{
		Type:       graph.NodeURL,
		PrimaryKey: "https://api.example.com/v1",
		Props: map[string]any{
			"url":      "https://api.example.com/v1",
			"host":     "api.example.com",
			"in_scope": true,
		},
	}

	if !sv.ShouldEnrich(node) {
		t.Fatal("expected in-scope URL to be enrichable")
	}
}

func TestShouldEnrichURLHostOutOfScope(t *testing.T) {
	sv := NewScopeValidator(&config.Config{Scope: config.ScopeConfig{Domains: []string{"example.com"}}})

	node := graph.Node{
		Type:       graph.NodeURL,
		PrimaryKey: "https://cdn.thirdparty.net/app.js",
		Props: map[string]any{
			"url":      "https://cdn.thirdparty.net/app.js",
			"host":     "cdn.thirdparty.net",
			"in_scope": true,
		},
	}

	if sv.ShouldEnrich(node) {
		t.Fatal("expected out-of-scope URL host to be blocked")
	}
}

func TestShouldEnrichIPAddressURLRespectsIPDirectHTTP(t *testing.T) {
	svDisabled := NewScopeValidator(&config.Config{Scope: config.ScopeConfig{IPDirect: false}})
	svEnabled := NewScopeValidator(&config.Config{Scope: config.ScopeConfig{IPDirect: true}})

	node := graph.Node{
		Type:       graph.NodeURL,
		PrimaryKey: "https://1.2.3.4/",
		Props: map[string]any{
			"url":      "https://1.2.3.4/",
			"in_scope": true,
		},
	}

	if svDisabled.ShouldEnrich(node) {
		t.Fatal("expected IP-direct URL blocked when ip_direct_http=false")
	}
	if !svEnabled.ShouldEnrich(node) {
		t.Fatal("expected IP-direct URL allowed when ip_direct_http=true and no CIDRs configured")
	}
}

func TestIsInScopeWithParent_URLNoLongerBlindlyInherits(t *testing.T) {
	sv := NewScopeValidator(&config.Config{Scope: config.ScopeConfig{Domains: []string{"example.com"}}})

	node := graph.Node{
		Type:       graph.NodeURL,
		PrimaryKey: "https://outside.net/",
		Props: map[string]any{
			"url": "https://outside.net/",
		},
	}

	if sv.IsInScopeWithParent(node, true) {
		t.Fatal("expected URL scope to be validated by host, not inherited blindly")
	}
}
