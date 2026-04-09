package engine

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/resistanceisuseless/autotron/internal/config"
	"github.com/resistanceisuseless/autotron/internal/graph"
	"github.com/resistanceisuseless/autotron/internal/parsers"
	"github.com/resistanceisuseless/autotron/internal/runner"
)

// Engine is the core dispatcher. It queries Neo4j for pending nodes, dispatches
// enricher jobs to a worker pool, persists results, and repeats until
// convergence or budget exhaustion.
type Engine struct {
	graphClient *graph.Client
	runner      *runner.Runner
	scope       *ScopeValidator
	dedup       *DedupTracker
	enrichers   []config.EnricherDef
	cfg         *config.Config
	logger      *slog.Logger

	// Per-enricher semaphores keyed by enricher name.
	semaphores map[string]chan struct{}
}

// NewEngine creates a new engine from the loaded configuration.
func NewEngine(
	graphClient *graph.Client,
	cfg *config.Config,
	enrichers []config.EnricherDef,
	logger *slog.Logger,
) *Engine {
	// Build per-enricher semaphores.
	sems := make(map[string]chan struct{}, len(enrichers))
	for _, e := range enrichers {
		conc := e.Concurrency
		if conc <= 0 {
			conc = 1
		}
		sems[e.Name] = make(chan struct{}, conc)
	}

	return &Engine{
		graphClient: graphClient,
		runner:      runner.NewRunner(logger.With("component", "runner")),
		scope:       NewScopeValidator(cfg),
		dedup:       NewDedupTracker(),
		enrichers:   enrichers,
		cfg:         cfg,
		logger:      logger.With("component", "engine"),
		semaphores:  sems,
	}
}

// Run executes the enrichment loop. It seeds the graph with the given domains,
// then dispatches enrichers in iterations until no new work is found or the
// budget is exhausted.
func (e *Engine) Run(ctx context.Context, domains []string) error {
	scanRunID := uuid.New().String()
	e.logger.Info("starting scan",
		"scan_run_id", scanRunID,
		"domains", domains,
		"max_iterations", e.cfg.Budget.MaxIterations,
	)

	// Seed domains into the graph.
	for _, domain := range domains {
		if err := e.graphClient.SeedDomain(ctx, domain, scanRunID); err != nil {
			return fmt.Errorf("seed domain %q: %w", domain, err)
		}
		e.logger.Info("seeded domain", "fqdn", domain)
	}

	// Main dispatch loop.
	for iteration := 1; iteration <= e.cfg.Budget.MaxIterations; iteration++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		dispatched, err := e.runIteration(ctx, iteration, scanRunID)
		if err != nil {
			return fmt.Errorf("iteration %d: %w", iteration, err)
		}

		e.logger.Info("iteration complete",
			"iteration", iteration,
			"dispatched", dispatched,
		)

		// Convergence: no new work dispatched.
		if dispatched == 0 {
			e.logger.Info("converged — no new work", "iterations", iteration)
			break
		}

		// Reset in-memory dedup between iterations (persistent state is in Neo4j).
		e.dedup.Reset()
	}

	e.logger.Info("scan complete", "scan_run_id", scanRunID)
	return nil
}

// runIteration runs a single pass over all enrichers, dispatching jobs for
// any pending nodes. Returns the total number of jobs dispatched.
func (e *Engine) runIteration(ctx context.Context, iteration int, scanRunID string) (int, error) {
	// Global worker pool.
	workerPool := make(chan struct{}, e.cfg.Budget.GlobalWorkers)

	var (
		wg         sync.WaitGroup
		mu         sync.Mutex
		totalJobs  int
		firstError error
	)

	for _, enricher := range e.enrichers {
		if ctx.Err() != nil {
			break
		}

		// Query pending nodes for this enricher.
		nodes, err := e.graphClient.QueryPendingNodes(
			ctx,
			enricher.Subscribes.NodeType,
			enricher.Name,
			enricher.Subscribes.Predicate,
		)
		if err != nil {
			e.logger.Error("query pending failed",
				"enricher", enricher.Name,
				"error", err,
			)
			continue
		}

		if len(nodes) == 0 {
			continue
		}

		e.logger.Debug("found pending nodes",
			"enricher", enricher.Name,
			"count", len(nodes),
		)

		for _, node := range nodes {
			if ctx.Err() != nil {
				break
			}

			// Skip nodes with empty primary keys (shouldn't happen, but guard).
			if node.PrimaryKey == "" {
				e.logger.Warn("skipping node with empty primary key",
					"enricher", enricher.Name, "type", enricher.Subscribes.NodeType)
				continue
			}

			// In-memory dedup within this iteration.
			if e.dedup.Check(node.PrimaryKey, enricher.Name) {
				continue
			}
			e.dedup.Mark(node.PrimaryKey, enricher.Name)

			mu.Lock()
			totalJobs++
			mu.Unlock()

			wg.Add(1)
			enricher := enricher // capture
			node := node         // capture

			go func() {
				defer wg.Done()

				// Acquire global worker slot.
				workerPool <- struct{}{}
				defer func() { <-workerPool }()

				// Acquire per-enricher semaphore.
				sem := e.semaphores[enricher.Name]
				sem <- struct{}{}
				defer func() { <-sem }()

				if err := e.dispatchJob(ctx, enricher, node, scanRunID); err != nil {
					e.logger.Error("job failed",
						"enricher", enricher.Name,
						"node", node.PrimaryKey,
						"error", err,
					)
					mu.Lock()
					if firstError == nil {
						firstError = err
					}
					mu.Unlock()
				}
			}()
		}
	}

	wg.Wait()

	// Individual job errors are logged but don't halt the iteration.
	// The engine continues processing all enrichers even when some fail.
	if firstError != nil {
		e.logger.Warn("iteration had errors (non-fatal)", "first_error", firstError)
	}
	return totalJobs, nil
}

// dispatchJob runs a single enricher against a single node: expand templates,
// execute the tool, parse output, persist results, mark enriched.
func (e *Engine) dispatchJob(ctx context.Context, enricher config.EnricherDef, node graph.Node, scanRunID string) error {
	start := time.Now()
	log := e.logger.With("enricher", enricher.Name, "node", node.PrimaryKey)

	// Look up the parser.
	parser, err := parsers.Get(enricher.Parser)
	if err != nil {
		return fmt.Errorf("get parser: %w", err)
	}

	// Build config values for template expansion.
	configVals := map[string]any{
		"resolvers_file": e.cfg.Scan.ResolversFile,
		"output_dir":     e.cfg.Scan.OutputDir,
	}

	// Expand command arguments.
	tmplData := BuildTemplateData(node, nil, scanRunID, configVals)
	expandedArgs, err := ExpandArgs(enricher.Command.Args, tmplData)
	if err != nil {
		return fmt.Errorf("expand args: %w", err)
	}

	// Expand stdin template if provided.
	expandedStdin, err := ExpandStdin(enricher.Command.Stdin, tmplData)
	if err != nil {
		return fmt.Errorf("expand stdin: %w", err)
	}

	// Execute the tool.
	runCfg := runner.RunConfig{
		Bin:     enricher.Command.Bin,
		Args:    expandedArgs,
		Stdin:   expandedStdin,
		Timeout: enricher.Command.Timeout,
	}

	result, err := e.runner.Run(ctx, runCfg)
	if err != nil {
		return fmt.Errorf("run tool: %w", err)
	}

	// Parse the output.
	parseResult, err := parser.Parse(ctx, node, result.StdoutReader(), result.StderrReader())
	if err != nil {
		log.Warn("parser error — marking enriched to avoid retry loop",
			"error", err,
			"duration", time.Since(start),
		)
		// Mark enriched even on parse error to avoid infinite retry.
		_ = e.graphClient.MarkEnriched(ctx, node.Type, node.PrimaryKey, enricher.Name)
		return fmt.Errorf("parse: %w", err)
	}

	// Persist results — scope-check each node before upsert.
	for _, n := range parseResult.Nodes {
		inScope := e.scope.IsInScope(n)
		n.Props["in_scope"] = inScope

		if _, err := e.graphClient.UpsertNode(ctx, n); err != nil {
			log.Error("upsert node failed", "node_type", n.Type, "key", n.PrimaryKey, "error", err)
			continue
		}

		// Out-of-scope nodes get a finding but no further enrichment.
		if !inScope {
			e.graphClient.UpsertFinding(ctx, graph.Finding{
				ID:         fmt.Sprintf("oos-%s-%s", n.Type, n.PrimaryKey),
				Type:       "out-of-scope-asset",
				Title:      fmt.Sprintf("Out-of-scope %s: %s", n.Type, n.PrimaryKey),
				Severity:   "info",
				Confidence: "confirmed",
				Tool:       enricher.Name,
				FirstSeen:  time.Now().UTC(),
				LastSeen:   time.Now().UTC(),
			}, n.Type, n.PrimaryKey)
		}
	}

	for _, edge := range parseResult.Edges {
		if err := e.graphClient.UpsertEdge(ctx, edge); err != nil {
			log.Error("upsert edge failed", "edge_type", edge.Type, "error", err)
		}
	}

	for _, finding := range parseResult.Findings {
		if err := e.graphClient.UpsertFinding(ctx, finding, node.Type, node.PrimaryKey); err != nil {
			log.Error("upsert finding failed", "finding_type", finding.Type, "error", err)
		}
	}

	// Mark the triggering node as enriched by this enricher.
	if err := e.graphClient.MarkEnriched(ctx, node.Type, node.PrimaryKey, enricher.Name); err != nil {
		return fmt.Errorf("mark enriched: %w", err)
	}

	log.Info("job complete",
		"nodes", len(parseResult.Nodes),
		"edges", len(parseResult.Edges),
		"findings", len(parseResult.Findings),
		"duration", time.Since(start),
	)
	return nil
}
