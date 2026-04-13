// Package config handles loading and validating the ASM pipeline configuration
// from YAML files. Two files: asm.yaml (global settings) and enrichers.yaml
// (tool pipeline definitions).
package config

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/resistanceisuseless/autotron/internal/graph"
	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration loaded from asm.yaml.
type Config struct {
	Neo4j  Neo4jConfig  `yaml:"neo4j"`
	Scope  ScopeConfig  `yaml:"scope"`
	Budget BudgetConfig `yaml:"budget"`
	Scan   ScanConfig   `yaml:"scan"`
}

// Neo4jConfig holds connection details for the graph database.
type Neo4jConfig struct {
	URI      string `yaml:"uri"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// ScopeConfig defines what's in-scope for enrichment. Nodes outside scope
// are recorded as findings but do not trigger further enrichment.
type ScopeConfig struct {
	Domains  []string `yaml:"domains"`        // suffix match (e.g. "example.com")
	CIDRs    []string `yaml:"cidrs"`          // CIDR ranges (e.g. "10.0.0.0/8")
	ASNs     []int    `yaml:"asns"`           // ASN numbers
	IPDirect bool     `yaml:"ip_direct_http"` // allow HTTP on bare IPs (default false)

	// Parsed at load time for fast lookup.
	parsedCIDRs []*net.IPNet
}

// BudgetConfig controls the explosion — hard limits on iterations and depth.
type BudgetConfig struct {
	MaxIterations     int `yaml:"max_iterations"`      // caps dispatcher passes (default 5)
	MaxDiscoveryDepth int `yaml:"max_discovery_depth"` // caps chain length (default 6)
	GlobalWorkers     int `yaml:"global_workers"`      // worker pool size (default NumCPU*2)
}

// ScanConfig holds runtime scan options.
type ScanConfig struct {
	ResolversFile string `yaml:"resolvers_file"`
	OutputDir     string `yaml:"output_dir"`
	JSReconBase   string `yaml:"jsrecon_base"`
}

// EnricherDef is a single tool invocation definition from enrichers.yaml.
type EnricherDef struct {
	Name        string          `yaml:"name"`        // unique, used as enriched_by stamp
	Parser      string          `yaml:"parser"`      // matches parser registry key
	Subscribes  SubscriptionDef `yaml:"subscribes"`  // what triggers this enricher
	Command     CommandDef      `yaml:"command"`     // how to invoke the tool
	Concurrency int             `yaml:"concurrency"` // per-enricher semaphore
	Enabled     bool            `yaml:"enabled"`
}

// SubscriptionDef defines what node type and predicate triggers an enricher.
type SubscriptionDef struct {
	NodeType  graph.NodeType `yaml:"node_type"`
	Predicate string         `yaml:"predicate"` // Cypher WHERE fragment
	Match     string         `yaml:"match"`     // optional Cypher pattern rooted at n
	Returns   []string       `yaml:"returns"`   // optional edge context fields
}

// CommandDef defines how to invoke an external tool.
type CommandDef struct {
	Bin     string        `yaml:"bin"`
	Args    []string      `yaml:"args"`
	Stdin   string        `yaml:"stdin"` // template piped to tool's stdin (optional)
	Timeout time.Duration `yaml:"timeout"`
	Retries int           `yaml:"retries"`
}

// EnrichersConfig is the top-level wrapper for enrichers.yaml.
type EnrichersConfig struct {
	Enrichers []EnricherDef `yaml:"enrichers"`
}

// LoadConfig reads and parses asm.yaml, applying defaults for unset fields.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	// Apply defaults.
	if cfg.Neo4j.URI == "" {
		cfg.Neo4j.URI = "bolt://localhost:7687"
	}
	if cfg.Neo4j.Username == "" {
		cfg.Neo4j.Username = "neo4j"
	}
	if cfg.Budget.MaxIterations == 0 {
		cfg.Budget.MaxIterations = 5
	}
	if cfg.Budget.MaxDiscoveryDepth == 0 {
		cfg.Budget.MaxDiscoveryDepth = 6
	}
	if cfg.Budget.GlobalWorkers == 0 {
		cfg.Budget.GlobalWorkers = runtime.NumCPU() * 2
	}
	if cfg.Scan.JSReconBase == "" {
		cfg.Scan.JSReconBase = "http://localhost:37232"
	}

	// Parse CIDRs for fast scope checking.
	for _, cidr := range cfg.Scope.CIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		cfg.Scope.parsedCIDRs = append(cfg.Scope.parsedCIDRs, ipNet)
	}

	return &cfg, nil
}

// LoadEnrichers reads and parses enrichers.yaml.
func LoadEnrichers(path string) (*EnrichersConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read enrichers %s: %w", path, err)
	}

	var cfg EnrichersConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse enrichers %s: %w", path, err)
	}

	// Validate: no duplicate names.
	seen := make(map[string]bool)
	for _, e := range cfg.Enrichers {
		if seen[e.Name] {
			return nil, fmt.Errorf("duplicate enricher name: %q", e.Name)
		}
		seen[e.Name] = true
	}

	return &cfg, nil
}

// EnabledEnrichers returns only the enricher definitions with enabled: true.
func (ec *EnrichersConfig) EnabledEnrichers() []EnricherDef {
	var enabled []EnricherDef
	for _, e := range ec.Enrichers {
		if e.Enabled {
			enabled = append(enabled, e)
		}
	}
	return enabled
}

// ParsedCIDRs returns the pre-parsed CIDR networks for scope checking.
func (c *Config) ParsedCIDRs() []*net.IPNet {
	return c.Scope.parsedCIDRs
}
