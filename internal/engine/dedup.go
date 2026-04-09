package engine

import (
	"crypto/sha256"
	"fmt"
	"sync"
)

// DedupTracker provides idempotency for the dispatch loop. It tracks which
// (node_key, enricher_name) pairs have been dispatched in the current scan run
// to avoid redundant subprocess invocations within a single iteration.
//
// Note: The persistent cycle brake is the enriched_by list on each Neo4j node.
// This in-memory tracker is a performance optimization that avoids re-querying
// Neo4j for nodes that were just dispatched in the same pass.
type DedupTracker struct {
	mu   sync.RWMutex
	seen map[string]bool
}

// NewDedupTracker creates a fresh dedup tracker.
func NewDedupTracker() *DedupTracker {
	return &DedupTracker{
		seen: make(map[string]bool),
	}
}

// key builds a deterministic hash for a (node_key, enricher_name) pair.
func key(nodeKey, enricherName string) string {
	h := sha256.Sum256([]byte(nodeKey + "|" + enricherName))
	return fmt.Sprintf("%x", h[:16])
}

// Check returns true if this (node, enricher) pair has already been dispatched.
func (d *DedupTracker) Check(nodeKey, enricherName string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.seen[key(nodeKey, enricherName)]
}

// Mark records that a (node, enricher) pair has been dispatched.
func (d *DedupTracker) Mark(nodeKey, enricherName string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen[key(nodeKey, enricherName)] = true
}

// Reset clears the tracker between iterations.
func (d *DedupTracker) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen = make(map[string]bool)
}

// Size returns the number of tracked pairs.
func (d *DedupTracker) Size() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.seen)
}
