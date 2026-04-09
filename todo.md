# Autotron ASM Pipeline — Todo List

## Status: Phase 1 COMPLETE + Scope inheritance implemented

Build: `go build ./...` clean, `go vet ./...` clean, `asm validate` reports 0 errors.

- **19 parsers registered** (18 real + 1 synthetic test)
- **52 enrichers loaded** (18 enabled, 34 disabled/stubbed)
- **0 validation errors**
- **Initial git commit done** (55d1208)

## Recent: Scope Redesign — IP inheritance from parent nodes

IPs discovered by resolving in-scope subdomains now automatically inherit
in-scope status. CIDRs in `asm.yaml` are optional (useful for pentests /
internal networks but not required for cloud-hosted targets).

### What changed:
- [x] `scope.go` — `IsInScopeWithParent()` method: IP nodes inherit scope from trigger node when no CIDR match
- [x] `engine.go` — `dispatchJob()` extracts trigger node's `in_scope` and passes to child scope checks
- [x] `engine.go` — CNAME chain ancestor check: out-of-scope CNAME intermediaries propagate scope if reachable from in-scope subdomain
- [x] `graph.go` — `HasInScopeAncestor()` query: traverses CNAME chains up to 10 hops to find in-scope origin
- [x] `asm.yaml` — CIDRs reverted to `[]`, documented as optional
- [x] Neo4j data fix — all 133 IP nodes updated to `in_scope=true`, stale out-of-scope findings removed

### Scope rules (updated):
1. **Domain/Subdomain**: suffix match against `scope.domains` (unchanged)
2. **IP**: match CIDR (if configured) OR inherit from in-scope trigger node OR inherit via CNAME chain ancestor
3. **Service/URL/etc.**: inherit from parent node (unchanged)

## Completed — Full Phase 1 scaffold

### Core infrastructure
- [x] git init repository
- [x] Initialize Go module (`github.com/resistanceisuseless/autotron`)
- [x] Create directory structure (cmd/asm, internal/{graph,engine,parsers,runner,config}, configs/)
- [x] Create .gitignore
- [x] `internal/graph/schema.go` — Node types, BaseNode, Finding, Edge, constraints, indexes
- [x] `internal/graph/graph.go` — Neo4j driver, session mgmt, generic upsert, schema init
- [x] `internal/parsers/parser.go` — Parser interface, Result struct, registry
- [x] `internal/engine/engine.go` — Dispatcher, worker pool, budget enforcement
- [x] `internal/engine/scope.go` — In-scope validation (domain suffix, CIDR, ASN, parent inheritance)
- [x] `internal/engine/dedup.go` — Seen-set / idempotency helpers
- [x] `internal/engine/template.go` — text/template expansion with validation
- [x] `internal/runner/runner.go` — Subprocess exec (timeout, stream capture, retry, stdin support)
- [x] `internal/config/config.go` — YAML loader, scope, budgets, enricher defs
- [x] `configs/asm.yaml` — Global config (scope, budgets, Neo4j conn)
- [x] `configs/enrichers.yaml` — 18 active + 34 stubbed tool entries (52 total)
- [x] `cmd/asm/main.go` — CLI entrypoint with cobra (scan, validate)
- [x] `internal/parsers/register/register.go` — blank-import package for parser init
- [x] `go mod tidy` — all dependencies resolved, clean build

### All 18 parser shapes implemented
- [x] hostname_list, subscope_json, ipintel_json, synthetic
- [x] dns_resolver, port_scan, nmap_xml
- [x] tls_audit
- [x] http_probe
- [x] webscope_jsonl, jsrecon_json
- [x] url_list, screenshot, param_discovery, secret_scanner
- [x] proxyhawk_json, nuclei_jsonl
- [x] web_vuln_generic, smb_enum

### Bug fixes (from first scan)
- [x] Engine error handling: runIteration non-fatal on job errors
- [x] Template missingkey=zero for runtime
- [x] nuclei_network predicate syntax
- [x] Empty-PrimaryKey guard
- [x] dnsx stdin fix (reads from stdin, not -d flag)

### Scope redesign
- [x] IP scope inherited from in-scope parent nodes
- [x] CNAME chain traversal for scope propagation
- [x] CIDRs optional in config

## Next Steps
- [ ] Re-run scan against campuscloud.io to exercise full pipeline (DNS → ports → HTTP → vulns)
- [ ] Fix subscope tool (exit code 2, no output)
- [ ] Consider moving wordlists out of git (174MB committed)
- [ ] Phase 2 planning (FindingSink, JSON export, LLM hooks, continuous monitoring)
