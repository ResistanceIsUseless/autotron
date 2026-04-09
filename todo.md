# Autotron ASM Pipeline — Todo List

## Status: All Phase 1 parsers COMPLETE

Build: `go build ./...` clean, `go vet ./...` clean, `asm validate` reports 0 errors.

- **19 parsers registered** (18 real + 1 synthetic test)
- **52 enrichers loaded** (22 enabled, 30 stubbed)
- **0 validation errors**

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
- [x] `internal/engine/scope.go` — In-scope validation (domain suffix, CIDR, ASN)
- [x] `internal/engine/dedup.go` — Seen-set / idempotency helpers
- [x] `internal/engine/template.go` — text/template expansion with validation
- [x] `internal/runner/runner.go` — Subprocess exec (timeout, stream capture, retry)
- [x] `internal/config/config.go` — YAML loader, scope, budgets, enricher defs
- [x] `configs/asm.yaml` — Global config (scope, budgets, Neo4j conn)
- [x] `configs/enrichers.yaml` — 22 active + 30 stubbed tool entries (52 total)
- [x] `cmd/asm/main.go` — CLI entrypoint with cobra (scan, validate)
- [x] `internal/parsers/register/register.go` — blank-import package for parser init
- [x] `go mod tidy` — all dependencies resolved, clean build

### Step 3: dns-walking (custom tools)
- [x] `internal/parsers/subscope_json.go` — subscope custom tool parser
- [x] `internal/parsers/ipintel_json.go` — ipintel custom tool parser
- [x] `internal/parsers/hostname_list.go` — hostname list parser (subfinder, amass, etc.)
- [x] `internal/parsers/synthetic.go` — synthetic test parser for loop verification

### Step 4: services-mapped
- [x] `internal/parsers/dns_resolver.go` — dnsx, puredns, shuffledns, massdns
- [x] `internal/parsers/port_scan.go` — naabu, masscan, rustscan
- [x] `internal/parsers/nmap_xml.go` — nmap (all NSE script variants)

### Step 5: cycles-working
- [x] `internal/parsers/tls_audit.go` — tlsx, testssl.sh, sslyze

### Step 6: web-discovered
- [x] `internal/parsers/http_probe.go` — httpx, webanalyze

### Step 7: web-enriched
- [x] `internal/parsers/webscope_jsonl.go` — webscope (custom)
- [x] `internal/parsers/jsrecon_json.go` — jsRecon (custom)

### Step 8: web-complete
- [x] `internal/parsers/url_list.go` — gau, waybackurls, katana, hakrawler, gospider, feroxbuster, ffuf
- [x] `internal/parsers/screenshot.go` — gowitness
- [x] `internal/parsers/param_discovery.go` — arjun, linkfinder
- [x] `internal/parsers/secret_scanner.go` — trufflehog, gitleaks

### Step 9: vulns-detected
- [x] `internal/parsers/proxyhawk_json.go` — proxyhawk (custom)
- [x] `internal/parsers/nuclei_jsonl.go` — nuclei (all template variants)

### Step 10: phase-1-complete
- [x] `internal/parsers/web_vuln_generic.go` — nikto, wapiti, dalfox, corsy
- [x] `internal/parsers/smb_enum.go` — enum4linux-ng, netexec

## Registered Parsers (19 total = 18 real + 1 synthetic)
1. hostname_list
2. subscope_json
3. ipintel_json
4. synthetic_test
5. dns_resolver
6. port_scan
7. nmap_xml
8. tls_audit
9. http_probe
10. webscope_jsonl
11. jsrecon_json
12. url_list
13. screenshot
14. param_discovery
15. secret_scanner
16. proxyhawk_json
17. nuclei_jsonl
18. web_vuln_generic
19. smb_enum

## File Count
- 22 Go source files (19 parsers + parser.go + register.go + main.go + graph + engine + runner + config)
- 2 YAML config files
- ~3000+ lines of Go
- ~800 lines of YAML

## Next Steps
- [ ] Initial git commit
- [ ] Integration testing with real Neo4j
- [ ] Phase 2 planning (FindingSink, LLM hooks, continuous monitoring)
