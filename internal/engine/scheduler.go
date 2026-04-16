package engine

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/resistanceisuseless/autotron/internal/config"
	"github.com/resistanceisuseless/autotron/internal/graph"
)

// scheduler is the continuous dispatcher. Instead of fixed iterations it runs
// one long-lived goroutine per enricher that polls for pending work, and a
// quiescence watchdog that exits when all enrichers are idle and no jobs are
// in-flight for a sustained period.
type scheduler struct {
	engine *Engine

	// Two shared worker pools: light (fast discovery) and heavy (nuclei/nikto).
	lightPool chan struct{}
	heavyPool chan struct{}

	// Per-enricher wake channels keyed by subscribed node type.
	// When a job produces nodes of type T, all enrichers subscribing to T wake.
	wakeMu   sync.RWMutex
	wakeByNT map[graph.NodeType][]chan struct{}

	// In-flight job counter for quiescence detection.
	inFlight atomic.Int64

	// Per-enricher "last had work" timestamp for quiescence.
	lastWorkMu sync.Mutex
	lastWork   map[string]time.Time

	scanRunID string
	logger    *slog.Logger
}

func newScheduler(engine *Engine, scanRunID string) *scheduler {
	s := &scheduler{
		engine:    engine,
		lightPool: make(chan struct{}, engine.cfg.Budget.GlobalWorkers),
		heavyPool: make(chan struct{}, engine.cfg.Budget.HeavyWorkers),
		wakeByNT:  make(map[graph.NodeType][]chan struct{}),
		lastWork:  make(map[string]time.Time),
		scanRunID: scanRunID,
		logger:    engine.logger.With("component", "scheduler"),
	}
	return s
}

// run starts one goroutine per enricher and waits for quiescence.
func (s *scheduler) run(ctx context.Context) error {
	// Create a cancellable context so we can stop enricher loops on quiescence.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup

	for _, enricher := range s.engine.enrichers {
		wake := make(chan struct{}, 1)

		// Register wake channel for this enricher's subscribed node type.
		s.wakeMu.Lock()
		nt := enricher.Subscribes.NodeType
		s.wakeByNT[nt] = append(s.wakeByNT[nt], wake)
		s.wakeMu.Unlock()

		wg.Add(1)
		go func(e config.EnricherDef, wake chan struct{}) {
			defer wg.Done()
			s.enricherLoop(ctx, e, wake)
		}(enricher, wake)
	}

	// Initial kick: wake all enrichers once.
	s.broadcastAll()

	// Quiescence watchdog — blocks until all enrichers idle.
	err := s.watchQuiescence(ctx)

	// Cancel enricher goroutines.
	cancel()

	// Wait for all enricher goroutines to finish.
	wg.Wait()
	return err
}

// enricherLoop is the long-running goroutine for a single enricher.
func (s *scheduler) enricherLoop(ctx context.Context, enricher config.EnricherDef, wake <-chan struct{}) {
	log := s.logger.With("enricher", enricher.Name)
	pollInterval := 2 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		case <-wake:
		case <-time.After(pollInterval):
		}

		if ctx.Err() != nil {
			return
		}

		dispatched := s.pollAndDispatch(ctx, enricher, log)
		if dispatched > 0 {
			s.lastWorkMu.Lock()
			s.lastWork[enricher.Name] = time.Now()
			s.lastWorkMu.Unlock()
		}
	}
}

// pollAndDispatch queries pending nodes for an enricher and dispatches jobs.
// Returns the number of jobs dispatched.
func (s *scheduler) pollAndDispatch(ctx context.Context, enricher config.EnricherDef, log *slog.Logger) int {
	pending, err := s.engine.graphClient.QueryPendingNodes(
		ctx,
		enricher.Subscribes.NodeType,
		enricher.Name,
		enricher.Subscribes.Predicate,
		enricher.Subscribes.Match,
		enricher.Subscribes.Returns,
	)
	if err != nil {
		log.Error("query pending failed", "error", err)
		return 0
	}

	if len(pending) == 0 {
		return 0
	}

	log.Debug("found pending nodes", "count", len(pending))

	dispatched := 0
	var wg sync.WaitGroup

	for _, work := range pending {
		if ctx.Err() != nil {
			break
		}

		node := work.Node

		if !s.engine.scope.ShouldEnrich(node) {
			log.Debug("skipping out-of-scope trigger node", "node", node.PrimaryKey, "type", node.Type)
			if err := s.engine.graphClient.MarkEnriched(ctx, node.Type, node.PrimaryKey, enricher.Name); err != nil {
				log.Warn("failed to mark skipped trigger enriched", "node", node.PrimaryKey, "error", err)
			}
			continue
		}

		depth := nodeDiscoveryDepth(node)
		if exceedsDiscoveryDepth(depth, s.engine.cfg.Budget.MaxDiscoveryDepth) {
			s.engine.handleDepthBudgetExceeded(ctx, enricher, node, depth, log)
			continue
		}

		if node.PrimaryKey == "" {
			log.Warn("skipping node with empty primary key", "type", enricher.Subscribes.NodeType)
			continue
		}

		edgeKey := edgePropsKey(work.EdgeProps)
		if s.engine.dedup.Check(node.PrimaryKey, edgeKey, enricher.Name) {
			continue
		}
		s.engine.dedup.Mark(node.PrimaryKey, edgeKey, enricher.Name)

		dispatched++

		// Pick worker pool based on weight.
		pool := s.lightPool
		if enricher.IsHeavy() {
			pool = s.heavyPool
		}

		s.inFlight.Add(1)
		wg.Add(1)
		enricher := enricher
		work := work

		go func() {
			defer wg.Done()
			defer s.inFlight.Add(-1)

			// Acquire pool slot.
			select {
			case pool <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-pool }()

			// Acquire per-enricher semaphore.
			sem := s.engine.semaphores[enricher.Name]
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			produced, err := s.engine.dispatchJobWithProduced(ctx, enricher, work, s.scanRunID)
			if err != nil {
				log.Error("job failed", "node", work.Node.PrimaryKey, "error", err)
			}

			// Wake downstream enrichers for any produced node types.
			if len(produced) > 0 {
				s.broadcastProduced(produced)
			}
		}()
	}

	wg.Wait()
	return dispatched
}

// broadcastProduced wakes enrichers subscribed to any of the produced node types.
func (s *scheduler) broadcastProduced(nodeTypes map[graph.NodeType]bool) {
	s.wakeMu.RLock()
	defer s.wakeMu.RUnlock()

	for nt := range nodeTypes {
		for _, ch := range s.wakeByNT[nt] {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}
}

// broadcastAll wakes every enricher.
func (s *scheduler) broadcastAll() {
	s.wakeMu.RLock()
	defer s.wakeMu.RUnlock()

	for _, channels := range s.wakeByNT {
		for _, ch := range channels {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}
}

// watchQuiescence blocks until all enrichers are idle with no in-flight jobs
// for a sustained period (3s), then cancels the context.
func (s *scheduler) watchQuiescence(ctx context.Context) error {
	const quiescenceTimeout = 3 * time.Second
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	quiescentSince := time.Time{}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if s.inFlight.Load() > 0 {
				quiescentSince = time.Time{}
				continue
			}

			// Check if any enricher had recent work.
			s.lastWorkMu.Lock()
			anyRecent := false
			for _, t := range s.lastWork {
				if time.Since(t) < quiescenceTimeout {
					anyRecent = true
					break
				}
			}
			s.lastWorkMu.Unlock()

			if anyRecent {
				quiescentSince = time.Time{}
				continue
			}

			// All quiet.
			if quiescentSince.IsZero() {
				quiescentSince = time.Now()
				continue
			}

			if time.Since(quiescentSince) >= quiescenceTimeout {
				s.logger.Info("quiescence detected — all enrichers idle", "sustained", quiescenceTimeout)
				return nil
			}
		}
	}
}
