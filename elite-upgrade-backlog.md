# Autotron Elite Upgrade Backlog

Goal: evolve Autotron from a strong Phase-1 scanner into an elite bug bounty research platform with high recall, high signal, and safe continuous operation.

## Success Criteria (Definition of Done)

- Attack surface recall improves without uncontrolled scan explosion.
- Findings are deduplicated, prioritized, and include reproducible evidence.
- Scope safety is strict (no out-of-scope active probing).
- Pipeline is testable end-to-end with deterministic fixtures.
- Incremental reruns are fast and auditable.

---

## Phase 0 - Correctness Hardening (P0)

### P0-1: Fix predicate precedence bug in dispatch query

- Problem: dispatch query appends raw predicates with `AND`, so unparenthesized `OR` clauses can bypass the `enriched_by` brake.
- Files:
  - `internal/graph/graph.go`
- Implementation:
  - Wrap enricher predicate in parentheses before appending to `WHERE` clauses.
  - Add defensive handling for whitespace-only predicates.
  - Keep `NOT '<enricher>' IN coalesce(n.enriched_by, [])` as mandatory outer clause.
- Acceptance criteria:
  - `QueryPendingNodes` never returns already-enriched nodes due to operator precedence.
  - Add test with predicate like `n.a = true OR n.b = true` proving brake still applies.

### P0-2: Enforce discovery depth budget

- Problem: `max_discovery_depth` exists in config but is not enforced in engine dispatch/persist flow.
- Files:
  - `internal/engine/engine.go`
  - `internal/graph/graph.go`
  - `internal/parsers/*` (only where depth assignment support is needed)
- Implementation:
  - Ensure child nodes receive `discovery_depth = parent_depth + 1` when absent.
  - Skip upsert/enrichment for nodes beyond budget and record a budget finding.
  - Prevent dispatch of nodes already beyond budget.
- Acceptance criteria:
  - No node persisted with `discovery_depth > max_discovery_depth`.
  - Engine converges with bounded growth on recursive discovery workloads.

### P0-3: Implement edge-context dispatch for template data

- Problem: templates support `.Edge.*`, but runtime always passes nil edge props.
- Files:
  - `internal/graph/graph.go`
  - `internal/engine/engine.go`
  - `internal/engine/template.go`
  - `internal/config/config.go` (if subscription schema needs edge pattern fields)
- Implementation:
  - Extend pending work query to return edge context where applicable.
  - Add a work-item type carrying node + edge props.
  - Feed edge props into `BuildTemplateData`.
- Acceptance criteria:
  - Enricher args can reliably use values like `{{.Edge.resolved_ip}}`.
  - Add integration test proving edge template expansion works.

### P0-4: Fix composite-key persistence semantics

- Problem: schema implies composite keys for `Technology`, `JSFile`, `Endpoint`, `Form`; upsert currently merges by one field.
- Files:
  - `internal/graph/schema.go`
  - `internal/graph/graph.go`
  - `internal/parsers/http_probe.go`
  - `internal/parsers/webscope_jsonl.go`
  - `internal/parsers/param_discovery.go`
  - `internal/parsers/jsrecon_json.go`
- Implementation (recommended approach):
  - Introduce explicit synthetic primary IDs (`tech_id`, `jsfile_id`, `endpoint_id`, `form_id`) built deterministically.
  - Store natural key fields separately as properties.
  - Update constraints/indexes and parser key generation consistently.
- Acceptance criteria:
  - No accidental node merges across different natural-key tuples.
  - Deterministic IDs remain stable across reruns.

### P0-5: Tighten scope enforcement for non-domain nodes

- Problem: services/URLs/endpoints can inherit scope too loosely from parent context.
- Files:
  - `internal/engine/scope.go`
  - `internal/engine/engine.go`
  - `internal/graph/graph.go`
- Implementation:
  - Validate URL host/domain lineage against in-scope roots.
  - Require explicit justification for inherited scope on external hostnames.
  - Add optional strict mode: only assets reachable from in-scope domain ancestry can be actively enriched.
- Acceptance criteria:
  - Out-of-scope hostnames are recorded but not actively scanned.
  - No regressions for CNAME chain in-scope propagation.

---

## Phase 1 - Reliability + Test Foundation (P0/P1)

### P1-1: Parser contract tests for all parser shapes

- Files:
  - `internal/parsers/*_test.go`
  - `internal/parsers/testdata/**`
- Implementation:
  - Add fixtures for valid, malformed, empty, truncated, and partial outputs.
  - Validate emitted nodes/edges/findings shape and idempotency behavior.
- Acceptance criteria:
  - Every parser has at least one success and one failure-mode test.

### P1-2: Engine integration tests (Neo4j)

- Files:
  - `internal/engine/engine_integration_test.go`
  - `internal/graph/graph_integration_test.go`
  - `docker-compose.test.yml` (optional)
- Implementation:
  - Use ephemeral Neo4j for full dispatch cycle testing.
  - Assert seed -> enrich -> mark-enriched -> converge behavior.
- Acceptance criteria:
  - Deterministic end-to-end tests for at least one DNS + HTTP + vuln path.

### P1-3: Typed job outcomes and retry policy

- Files:
  - `internal/runner/runner.go`
  - `internal/engine/engine.go`
- Implementation:
  - Distinguish `no_data`, `transient_error`, `fatal_error`.
  - Retry transient failures with backoff; avoid infinite retries.
  - Do not mark enriched on fatal parse failures without recording state.
- Acceptance criteria:
  - Error handling is explicit and observable in logs.
  - Repeated EOF/no-output cases do not cause noisy rerun loops.

### P1-4: Upgrade `asm validate`

- Files:
  - `cmd/asm/main.go`
  - `internal/config/config.go`
  - `internal/graph/graph.go`
- Implementation:
  - Add predicate compile checks against Neo4j via `EXPLAIN`.
  - Validate command binaries exist (for enabled enrichers) when requested (`--strict-tools`).
  - Validate template variables against schema-aware synthetic context.
- Acceptance criteria:
  - `asm validate` fails early on bad predicates/tool wiring.

---

## Phase 2 - Elite Recon Depth (P1)

### P2-1: Multi-source asset expansion

- Expand active discovery from current baseline to include ASN/CIDR expansion, CT loops, JS-host extraction loops, and API endpoint enrichment where safe.

### P2-2: Adaptive scan tiers

- Introduce tiered execution:
  - Tier A: fast wide recon
  - Tier B: focused service/web enrichment
  - Tier C: deep targeted probes
- Support per-tier budgets and per-target tool packs.

### P2-3: Tool capability matrix

- Replace static enablement assumptions with host/tool capability checks (installed binary, auth requirements, expected output mode).

---

## Phase 3 - Elite Vulnerability Workflow (P1)

### P3-1: Verification modules for key classes

- Add secondary verification logic for high-value bug classes (XSS, SSRF, open redirect, takeover).

### P3-2: Finding correlation and dedup engine

- Canonicalize equivalent findings from multiple tools into one finding record with evidence rollup.

### P3-3: Exploitability-aware confidence scoring

- Score findings by exploitability signals (reachability, auth context, internet exposure, known exploit references).

---

## Phase 4 - Prioritization Intelligence (P1/P2)

### P4-1: Risk scoring model

- Compute triage priority: severity x confidence x exploitability x exposure x business impact proxy.

### P4-2: Context decorators

- Add optional EPSS/KEV/CVE metadata decoration pipeline for faster triage.

### P4-3: Reporting outputs

- Deliver three output modes:
  - Research queue (action-first)
  - Executive summary
  - Machine-readable export for sinks

---

## Phase 5 - Continuous Monitoring Operations (P2)

### P5-1: Incremental scanning

- Rerun based on change detection and stale-node policies instead of full replay.

### P5-2: Observability and SLOs

- Track parser success rate, dispatch latency, finding yield per tool, and error classes.

### P5-3: Guardrails

- Add stricter rate/scope/wordlist governance and global kill-switch behavior.

---

## Immediate Execution Order (first 2 weeks)

1. P0-1 predicate precedence fix + tests.
2. P0-4 composite key semantics refactor.
3. P0-2 discovery depth enforcement.
4. P1-1 parser contract tests for currently enabled parser set.
5. P1-4 `asm validate` predicate compile checks.

---

## Verification Checklist (run per milestone)

- `go test ./...`
- `go vet ./...`
- `go run ./cmd/asm validate`
- End-to-end smoke scan on a controlled domain.
- Confirm no out-of-scope active enrichment occurs.
- Confirm rerun convergence and stable finding IDs.
