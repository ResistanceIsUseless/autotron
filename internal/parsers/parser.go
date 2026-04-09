// Package parsers defines the Parser interface and a global registry.
// One Parser per tool OUTPUT SHAPE (not per tool). Many tools share shapes:
// subfinder, assetfinder, amass all emit hostname lists and share one parser.
//
// Adding a new tool that fits an existing shape is a YAML-only change.
// Adding a tool with a genuinely new output shape is one new parser file
// plus one YAML entry.
package parsers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

// ErrNotImplemented is returned by stub parsers that aren't wired up yet.
var ErrNotImplemented = errors.New("parser not implemented")

// Result holds the graph mutations produced by a single parser invocation.
// The engine persists these — parsers never write to Neo4j directly.
type Result struct {
	Nodes    []graph.Node    // New or updated nodes
	Edges    []graph.Edge    // Relationships to create
	Findings []graph.Finding // Vulns / observations
}

// Parser converts a tool's raw output into graph mutations.
// One Parser per tool OUTPUT SHAPE (not per tool).
type Parser interface {
	// Name returns the stable identifier that matches the `parser:` field in
	// enrichers.yaml. Changing it triggers re-runs on every existing node.
	Name() string

	// Parse consumes stdout/stderr for a single tool run and emits graph
	// mutations. The triggering node is passed so results attach correctly.
	// Must be idempotent: same input + same trigger = same Result.
	Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error)
}

// registry holds all registered parsers, keyed by Name().
var (
	registryMu sync.RWMutex
	registry   = make(map[string]Parser)
)

// Register adds a parser to the global registry. Panics on duplicate names
// to catch wiring bugs at init time.
func Register(p Parser) {
	registryMu.Lock()
	defer registryMu.Unlock()

	name := p.Name()
	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("duplicate parser registration: %q", name))
	}
	registry[name] = p
}

// Get returns the parser registered under the given name, or an error if
// no parser is registered.
func Get(name string) (Parser, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	p, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("no parser registered for %q", name)
	}
	return p, nil
}

// Names returns a sorted list of all registered parser names. Useful for
// config validation at startup.
func Names() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}

// Reset clears the registry. Only for testing.
func Reset() {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry = make(map[string]Parser)
}
