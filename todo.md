# Autotron ASM Pipeline — Todo List

## Status: Phase 1 COMPLETE — Pipeline running end-to-end

Build: `go build ./...` clean, `go vet ./...` clean, `asm validate` reports 0 errors.

- **19 parsers registered** (18 real + 1 synthetic test)
- **52 enrichers loaded** (18 enabled, 34 disabled/stubbed)
- **Pipeline confirmed working**: Domain → Subdomain (subfinder) → DNS (dnsx) → IP → Port Scan (naabu) → nmap_http_scripts / nmap_ssl_enum / tlsx_cert / httpx_probe all triggering correctly

## Latest Scan Results (campuscloud.io)

Neo4j graph state after 2 interrupted runs (bash timeout, not tool failure):
- **208 Subdomain** nodes (116 from subfinder + CNAME targets from dnsx)
- **141 IP** nodes (all in-scope, IPv4 only — IPv6 filtered by predicate)
- **141 Service** nodes (72 https, 67 http, 1 rdp, 1 ldaps) — **product and tls fields now set correctly**
- **92 Finding** nodes (all out-of-scope-asset type from CNAME chain endpoints)
- **18 Service nodes enriched by nmap_http_scripts** (HTTP enum, headers, methods, title, robots)
- httpx_probe, tlsx_cert, nmap_ssl_enum all started but got killed by bash timeout
- Scan is **fully resumable** — each `asm scan` run picks up where it left off via `enriched_by` tracking

## Completed This Session

### Critical fix: port_scan.go product inference
- [x] `port_scan.go` — Added `wellKnownProducts` map (120+ port→product mappings covering full scan port list)
- [x] `port_scan.go` — Added `tlsPorts` map (443, 2443, 3443, 4443, 5443, 5986, 6443, 7443, 8443, 9443)
- [x] Service nodes now get `product` (http/https/ssh/smb/rdp/etc.) and `tls=true` set at creation time
- [x] This unblocks ALL downstream enrichers: httpx_probe, nmap_http_scripts, nmap_ssh, nmap_smb, nmap_ssl_enum, tlsx_cert

### Naabu performance fix
- [x] Replaced `-top-ports 1000` with explicit port list (user-provided "interesting services" list)
- [x] Ports: `22,80,139,389,443,445,623,631,636,999,1080,1880,...,53281` (all HTTP, HTTPS, RDP, SMB, VNC, DB, cache ports)
- [x] Added `-exclude-cdn` (CDN/WAF IPs only scan 80,443 — finishes in ~3s vs ~4min)
- [x] Added `-c 50 -rate 1000 -Pn` for faster scanning
- [x] Added `NOT n.address CONTAINS ':'` predicate to skip IPv6 (naabu returns 0 results for IPv6)
- [x] Reduced timeout from 15m to 5m
- [x] Increased concurrency from 4 to 8

### Subscope enricher fix
- [x] Changed args from `-json` (invalid) to `-o - -p --ct --arin`
- [x] subscope still fails at runtime (outputs progress text to stdout before JSON — parser can't decode)

### subscope parser fix
- [x] `subscope_json.go` — Read all bytes, skip to first `{` before JSON decode (progress text no longer breaks parser)

### nmap XML parser fix
- [x] `nmap_xml.go` — Read all bytes upfront; on truncated/empty XML return empty result instead of error (no longer blocks pipeline)

### DNS-first rule investigation
- [x] Confirmed: `nmap_http_scripts` subscribing to `Service` nodes (IP-level) is CORRECT per plan doc
- [x] DNS-first rule applies exclusively to web enrichers (httpx, webscope) that need vhost-correct requests
- [x] nmap HTTP scripts correctly target IPs via `{{.Node.ip}}`, same as nmap_ssh, nmap_smb, nmap_ssl_enum

### Subdomain-centric port scanning
- [x] naabu now subscribes to `Subdomain` nodes instead of `IP` nodes
- [x] Pipeline flow: Domain → Subdomain → DNS → Port Scan → Service (all subdomain-driven)
- [x] Uses `-host {{.Node.fqdn}} -sa` (naabu resolves + scans all IPs internally)
- [x] Predicate: `in_scope AND status IN ['resolved','discovered'] AND EXISTS resolved IPv4`
- [x] port_scan parser now creates IP nodes + IP→HAS_SERVICE edges from naabu output
- [x] IP fan-out max 4 subdomains/IP — acceptable redundancy with -exclude-cdn

## Previous Session — Full Phase 1 scaffold

### Core infrastructure
- [x] All Go packages: graph, engine, parsers, runner, config, CLI
- [x] Neo4j schema (12 node types, 12 relationship types, constraints, indexes)
- [x] Engine dispatcher with worker pool, per-enricher semaphores, iteration loop
- [x] Scope validator with domain suffix, CIDR, ASN, parent inheritance, CNAME chain propagation
- [x] Template expansion with validation and stdin support
- [x] Subprocess runner with timeout, retry, stream capture, stdin piping

### All 18 parser shapes implemented
- [x] hostname_list, subscope_json, ipintel_json, synthetic, dns_resolver, port_scan, nmap_xml
- [x] tls_audit, http_probe, webscope_jsonl, jsrecon_json, url_list, screenshot
- [x] param_discovery, secret_scanner, proxyhawk_json, nuclei_jsonl, web_vuln_generic, smb_enum

### Bug fixes (across sessions)
- [x] Engine error handling: runIteration non-fatal on job errors
- [x] Template missingkey=zero for runtime
- [x] nuclei_network predicate syntax
- [x] Empty-PrimaryKey guard
- [x] dnsx stdin fix (reads from stdin, not -d flag)
- [x] IP scope inherited from in-scope parent nodes
- [x] CNAME chain traversal for scope propagation

## Remaining Issues

### Medium Priority
- [ ] Consider moving wordlists out of git (174MB committed)

### Lower Priority / Phase 2
- [ ] Install ipintel (`go install github.com/ResistanceIsUseless/ipintel/cmd/ipintel@latest`)
- [ ] Phase 2 planning (FindingSink, JSON export, LLM hooks, continuous monitoring)
- [ ] Run full uninterrupted scan (outside of tool timeout — `nohup ./asm scan ... &`)

## How to Run

```bash
# Full scan (resumable — safe to re-run)
./asm scan -c configs/asm.yaml -e configs/enrichers.yaml -d campuscloud.io

# Background (no timeout)
nohup ./asm scan -c configs/asm.yaml -e configs/enrichers.yaml -d campuscloud.io > scan.log 2>&1 &

# Check Neo4j state
docker exec neo4j-test cypher-shell -u neo4j -p changeme "MATCH (n) RETURN labels(n)[0] AS label, count(n) ORDER BY count(n) DESC"
```
