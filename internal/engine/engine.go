package engine

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
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
	metrics     *runMetrics
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
func (e *Engine) Run(ctx context.Context, domains []string) (err error) {
	scanRunID := uuid.New().String()
	startedAt := time.Now().UTC()
	target := strings.Join(domains, ",")
	e.metrics = newRunMetrics()

	if _, upsertErr := e.graphClient.UpsertNode(ctx, graph.Node{
		Type:       graph.NodeScanRun,
		PrimaryKey: scanRunID,
		Props: map[string]any{
			"id":           scanRunID,
			"target":       target,
			"domains":      domains,
			"domain_count": len(domains),
			"status":       "running",
			"started_at":   startedAt.Format(time.RFC3339),
		},
	}); upsertErr != nil {
		e.logger.Warn("failed to persist scan run start", "scan_run_id", scanRunID, "error", upsertErr)
	}

	defer func() {
		status := "completed"
		if err != nil {
			if ctx.Err() != nil {
				status = "cancelled"
			} else {
				status = "failed"
			}
		}

		if _, upsertErr := e.graphClient.UpsertNode(context.Background(), graph.Node{
			Type:       graph.NodeScanRun,
			PrimaryKey: scanRunID,
			Props: map[string]any{
				"id":            scanRunID,
				"target":        target,
				"domains":       domains,
				"domain_count":  len(domains),
				"status":        status,
				"started_at":    startedAt.Format(time.RFC3339),
				"completed_at":  time.Now().UTC().Format(time.RFC3339),
				"duration_ms":   time.Since(startedAt).Milliseconds(),
				"error_message": errorString(err),
			},
		}); upsertErr != nil {
			e.logger.Warn("failed to persist scan run completion", "scan_run_id", scanRunID, "error", upsertErr)
		}

		if status == "completed" && strings.TrimSpace(e.cfg.Scan.OutputDir) != "" {
			if writeErr := writeDeltaSummary(e.cfg.Scan.OutputDir, e.metrics.Summary(scanRunID, startedAt)); writeErr != nil {
				e.logger.Warn("failed to write delta summary", "scan_run_id", scanRunID, "error", writeErr)
			}
		}
	}()

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
		e.metrics.AddNode(graph.NodeDomain, domain, true)
		e.logger.Info("seeded domain", "fqdn", domain)
	}

	// Main dispatch loop — use the continuous scheduler.
	sched := newScheduler(e, scanRunID)
	if err := sched.run(ctx); err != nil && err != context.Canceled {
		return fmt.Errorf("scheduler: %w", err)
	}

	e.logger.Info("scan complete", "scan_run_id", scanRunID)
	return nil
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// handleDepthBudgetExceeded logs and records a finding for a node that exceeds
// the discovery depth budget, then marks it enriched.
func (e *Engine) handleDepthBudgetExceeded(ctx context.Context, enricher config.EnricherDef, node graph.Node, depth int, log *slog.Logger) {
	log.Warn("skipping node beyond discovery depth budget",
		"node", node.PrimaryKey,
		"depth", depth,
		"max_depth", e.cfg.Budget.MaxDiscoveryDepth,
	)
	findingID := depthBudgetFindingID(enricher.Name, node.Type, node.PrimaryKey, depth)
	if err := e.graphClient.UpsertFinding(ctx, graph.Finding{
		ID:         findingID,
		Type:       "discovery-depth-budget-exceeded",
		Title:      fmt.Sprintf("Skipped enrichment beyond discovery depth budget: %s", node.PrimaryKey),
		Severity:   "info",
		Confidence: "confirmed",
		Tool:       enricher.Name,
		Evidence: map[string]any{
			"node_type": node.Type,
			"node_key":  node.PrimaryKey,
			"depth":     depth,
			"max_depth": e.cfg.Budget.MaxDiscoveryDepth,
		},
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}, node.Type, node.PrimaryKey); err != nil {
		log.Warn("failed to upsert depth budget finding", "node", node.PrimaryKey, "error", err)
	} else {
		e.metrics.AddFinding(findingID, "info")
	}
	if err := e.graphClient.MarkEnriched(ctx, node.Type, node.PrimaryKey, enricher.Name); err != nil {
		log.Warn("failed to mark over-budget node enriched", "node", node.PrimaryKey, "error", err)
	}
}

// dispatchJobWithProduced runs a single enricher against a single node: expand
// templates, execute the tool, parse output, persist results, mark enriched.
// It returns the set of node types that were produced so the scheduler can
// wake downstream enrichers immediately.
func (e *Engine) dispatchJobWithProduced(ctx context.Context, enricher config.EnricherDef, work graph.PendingWork, scanRunID string) (map[graph.NodeType]bool, error) {
	node := work.Node
	start := time.Now()
	log := e.logger.With("enricher", enricher.Name, "node", node.PrimaryKey)
	produced := make(map[graph.NodeType]bool)

	// Look up the parser.
	parser, err := parsers.Get(enricher.Parser)
	if err != nil {
		return nil, fmt.Errorf("get parser: %w", err)
	}

	// Build config values for template expansion.
	configVals := map[string]any{
		"resolvers_file": e.cfg.Scan.ResolversFile,
		"output_dir":     e.cfg.Scan.OutputDir,
	}

	// Expand command arguments.
	tmplData := BuildTemplateData(node, work.EdgeProps, scanRunID, configVals)
	expandedArgs, err := ExpandArgs(enricher.Command.Args, tmplData)
	if err != nil {
		return nil, fmt.Errorf("expand args: %w", err)
	}

	// Expand stdin template if provided.
	expandedStdin, err := ExpandStdin(enricher.Command.Stdin, tmplData)
	if err != nil {
		return nil, fmt.Errorf("expand stdin: %w", err)
	}

	// Execute the tool.
	runCfg := runner.RunConfig{
		Bin:     enricher.Command.Bin,
		Args:    expandedArgs,
		Stdin:   expandedStdin,
		Timeout: enricher.Command.Timeout,
		Retries: enricher.Command.Retries,
	}

	result, err := e.runner.Run(ctx, runCfg)
	if err != nil {
		outcome := classifyRunError(err)
		if outcome == jobOutcomeTransient {
			log.Warn("transient runner failure",
				"error", err,
				"outcome", outcome,
				"duration", time.Since(start),
			)
			return nil, fmt.Errorf("run tool transient: %w", err)
		}

		log.Error("fatal runner failure — marking enriched",
			"error", err,
			"outcome", outcome,
			"duration", time.Since(start),
		)
		_ = e.graphClient.MarkEnriched(ctx, node.Type, node.PrimaryKey, enricher.Name)
		return nil, fmt.Errorf("run tool: %w", err)
	}

	if result.Stdout.Len() == 0 && result.Stderr.Len() == 0 {
		if err := e.graphClient.MarkEnriched(ctx, node.Type, node.PrimaryKey, enricher.Name); err != nil {
			return nil, fmt.Errorf("mark enriched after no-data: %w", err)
		}
		log.Info("job complete", "nodes", 0, "edges", 0, "findings", 0, "duration", time.Since(start), "outcome", jobOutcomeNoData)
		return nil, nil
	}

	// Parse the output.
	parseResult, err := parser.Parse(ctx, node, result.StdoutReader(), result.StderrReader())
	if err != nil {
		outcome := classifyParseError(err)
		log.Warn("parser error — marking enriched to avoid retry loop",
			"error", err,
			"outcome", outcome,
			"duration", time.Since(start),
		)
		_ = e.graphClient.MarkEnriched(ctx, node.Type, node.PrimaryKey, enricher.Name)
		return nil, fmt.Errorf("parse: %w", err)
	}

	// Persist results — scope-check each node before upsert.
	triggerInScope := false
	if v, ok := node.Props["in_scope"]; ok {
		if b, ok := v.(bool); ok {
			triggerInScope = b
		}
	}
	if !triggerInScope && node.Type == graph.NodeSubdomain {
		if fqdn, _ := node.Props["fqdn"].(string); fqdn != "" {
			if hasAncestor, err := e.graphClient.HasInScopeAncestor(ctx, fqdn); err == nil && hasAncestor {
				triggerInScope = true
				log.Debug("trigger inherits scope via CNAME chain", "fqdn", fqdn)
			}
		}
	}

	skippedByDepth := make(map[graph.NodeType]map[string]bool)

	for _, n := range parseResult.Nodes {
		depth := resolveChildDepth(node, n)
		n.Props["discovery_depth"] = depth
		if exceedsDiscoveryDepth(depth, e.cfg.Budget.MaxDiscoveryDepth) {
			if skippedByDepth[n.Type] == nil {
				skippedByDepth[n.Type] = make(map[string]bool)
			}
			skippedByDepth[n.Type][n.PrimaryKey] = true

			findingID := depthBudgetFindingID(enricher.Name, n.Type, n.PrimaryKey, depth)
			if err := e.graphClient.UpsertFinding(ctx, graph.Finding{
				ID:         findingID,
				Type:       "discovery-depth-budget-exceeded",
				Title:      fmt.Sprintf("Skipped %s beyond discovery depth budget: %s", n.Type, n.PrimaryKey),
				Severity:   "info",
				Confidence: "confirmed",
				Tool:       enricher.Name,
				Evidence: map[string]any{
					"node_type":   n.Type,
					"node_key":    n.PrimaryKey,
					"depth":       depth,
					"max_depth":   e.cfg.Budget.MaxDiscoveryDepth,
					"parent_node": node.PrimaryKey,
				},
				FirstSeen: time.Now().UTC(),
				LastSeen:  time.Now().UTC(),
			}, node.Type, node.PrimaryKey); err != nil {
				log.Error("upsert depth budget finding failed", "node_type", n.Type, "key", n.PrimaryKey, "error", err)
			} else {
				e.metrics.AddFinding(findingID, "info")
			}
			continue
		}

		inScope := e.scope.IsInScopeWithParent(n, triggerInScope)
		n.Props["in_scope"] = inScope

		if _, err := e.graphClient.UpsertNode(ctx, n); err != nil {
			log.Error("upsert node failed", "node_type", n.Type, "key", n.PrimaryKey, "error", err)
			continue
		}
		produced[n.Type] = true
		e.metrics.AddNode(n.Type, n.PrimaryKey, inScope)

		if !inScope {
			if err := e.graphClient.UpsertFinding(ctx, graph.Finding{
				ID:         fmt.Sprintf("oos-%s-%s", n.Type, n.PrimaryKey),
				Type:       "out-of-scope-asset",
				Title:      fmt.Sprintf("Out-of-scope %s: %s", n.Type, n.PrimaryKey),
				Severity:   "info",
				Confidence: "confirmed",
				Tool:       enricher.Name,
				FirstSeen:  time.Now().UTC(),
				LastSeen:   time.Now().UTC(),
			}, n.Type, n.PrimaryKey); err == nil {
				e.metrics.AddFinding(fmt.Sprintf("oos-%s-%s", n.Type, n.PrimaryKey), "info")
			}
		}
	}

	for _, edge := range parseResult.Edges {
		if skippedByDepth[edge.FromType] != nil && skippedByDepth[edge.FromType][edge.FromKey] {
			continue
		}
		if skippedByDepth[edge.ToType] != nil && skippedByDepth[edge.ToType][edge.ToKey] {
			continue
		}
		if err := e.graphClient.UpsertEdge(ctx, edge); err != nil {
			log.Error("upsert edge failed", "edge_type", edge.Type, "error", err)
		}
	}

	for _, finding := range parseResult.Findings {
		if err := e.graphClient.UpsertFinding(ctx, finding, node.Type, node.PrimaryKey); err != nil {
			log.Error("upsert finding failed", "finding_type", finding.Type, "error", err)
		} else {
			e.metrics.AddFinding(finding.ID, finding.Severity)
		}
	}

	// Mark the triggering node as enriched by this enricher.
	if err := e.graphClient.MarkEnriched(ctx, node.Type, node.PrimaryKey, enricher.Name); err != nil {
		return produced, fmt.Errorf("mark enriched: %w", err)
	}

	log.Info("job complete",
		"nodes", len(parseResult.Nodes),
		"edges", len(parseResult.Edges),
		"findings", len(parseResult.Findings),
		"duration", time.Since(start),
		"outcome", jobOutcomeSuccess,
	)
	return produced, nil
}

func edgePropsKey(edgeProps map[string]any) string {
	if len(edgeProps) == 0 {
		return ""
	}

	keys := make([]string, 0, len(edgeProps))
	for k := range edgeProps {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, edgeProps[k]))
	}

	return strings.Join(parts, "|")
}
