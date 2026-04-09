# Attack Surface Monitoring Pipeline — Implementation Plan

**Status:** Phase 1 design, pre-implementation
**Language:** Go
**Data store:** Neo4j
**Custom tools:** subscope, ipintel, webscope, jsRecon, proxyhawk

---

## 1. Guiding Principles

These are the non-negotiables that every design decision should trace back to. If a later choice conflicts with one of these, the choice is wrong.

1. **Data-type-driven enrichment, not stage-driven execution.** Stages are a human mental model; the runtime thinks in terms of "a node appeared — who subscribes to this node type?"
2. **Neo4j is the source of truth.** Enrichers are stateless; all state lives in the graph.
3. **Enrichers never write to Neo4j directly.** They return structs. The engine persists. One place to enforce scope, dedup, and rate limiting.
4. **Cycles are implicit, not special-cased.** When a new node enters the graph, its subscribers fire.
5. **DNS-first for HTTP.** Web enrichers subscribe to `Subdomain` nodes, not bare IPs. The resolved IP is carried on the edge for vhost-correct requests.
6. **Scope is enforced on every upsert, not at the edges.** Out-of-scope nodes are recorded as findings but do not trigger further enrichment.
7. **Parsers are code, invocations are config.** Go handles tool output shapes; YAML handles "run this command against these nodes with these args."
8. **Keep the file count low.** One package per real concern. One parser file per output *shape*, not per tool.
9. **No mock data.** If a tool isn't wired up yet, its YAML entry has `enabled: false`. Stubs return `ErrNotImplemented`, never fake output.

---

## 2. Project Layout

```
asm/
├── cmd/asm/main.go               # CLI entrypoint (cobra)
├── internal/
│   ├── graph/
│   │   ├── graph.go              # Neo4j driver, session mgmt, generic upsert
│   │   └── schema.go             # Node types, constraints, indexes
│   ├── engine/
│   │   ├── engine.go             # Dispatcher, worker pool, budget enforcement
│   │   ├── scope.go              # In-scope validation
│   │   ├── dedup.go              # Seen-set / idempotency helpers
│   │   └── template.go           # text/template expansion for command args
│   ├── parsers/                  # One file per output SHAPE (not per tool)
│   │   ├── parser.go             # Parser interface + registry
│   │   ├── hostname_list.go      # subfinder, assetfinder, amass, crt.sh, dnstwist...
│   │   ├── dns_resolver.go       # dnsx, puredns, shuffledns, massdns
│   │   ├── port_scan.go          # naabu, masscan, rustscan
│   │   ├── nmap_xml.go           # nmap (all NSE script variants)
│   │   ├── http_probe.go         # httpx, webanalyze
│   │   ├── url_list.go           # gau, waybackurls, katana, hakrawler, gospider, feroxbuster, ffuf
│   │   ├── tls_audit.go          # tlsx, testssl.sh, sslyze
│   │   ├── nuclei_jsonl.go       # nuclei (all template variants)
│   │   ├── secret_scanner.go     # trufflehog, gitleaks
│   │   ├── smb_enum.go           # enum4linux-ng, netexec
│   │   ├── screenshot.go         # gowitness
│   │   ├── param_discovery.go    # arjun, linkfinder
│   │   ├── web_vuln_generic.go   # nikto, wapiti, dalfox, corsy
│   │   ├── subscope_json.go      # subscope (custom)
│   │   ├── webscope_jsonl.go     # webscope (custom)
│   │   ├── jsrecon_json.go       # jsRecon (custom)
│   │   ├── proxyhawk_json.go     # proxyhawk (custom)
│   │   └── ipintel_json.go       # ipintel (custom)
│   ├── runner/
│   │   └── runner.go             # Subprocess exec (timeout, stream capture, retry)
│   └── config/
│       └── config.go             # YAML loader, scope, budgets, tool paths
├── configs/
│   ├── asm.yaml                  # Global config (scope, budgets, Neo4j conn)
│   └── enrichers.yaml            # Pipeline definition (all tools, enabled/disabled)
└── go.mod
```

Roughly 18 Go files for the scaffold + 18 parser files. Adding a new tool that fits an existing shape is a YAML edit only. Adding a tool with a genuinely new shape is one new parser file + one YAML entry.

---

## 3. Architecture: Parsers vs Commands

The core design decision that lets us handle 60+ tools without 60+ code paths.

### 3.1 Parser = code, Invocation = config

Every tool has two concerns:

1. **Parsing its output into graph nodes** — needs types, error handling, JSON/XML stream processing, hashing. This is a code problem. One Go file per output *shape*.
2. **When to run it, with what args, against which nodes** — subscription predicate, CLI flags, concurrency, timeout. This is a config problem. Lives in `enrichers.yaml`.

Splitting this way means adding a new nmap NSE script set is a YAML block copy — no recompile. Adding an entirely new tool that outputs nmap-style XML is zero new code, one YAML entry.

### 3.2 The Parser interface

```go
// Parser converts a tool's raw output into graph mutations.
// One Parser per tool OUTPUT SHAPE (not per tool). Many tools share shapes:
// subfinder, assetfinder, amass, and crt.sh all emit hostname lists.
type Parser interface {
    // Name matches the `parser:` field in enrichers.yaml.
    // Stable identifier — changing it triggers re-runs on every existing node.
    Name() string

    // Parse consumes stdout/stderr for a single tool run and emits graph
    // mutations. The triggering node is passed so results attach correctly.
    // Must be idempotent: same input + same trigger = same Result.
    Parse(ctx context.Context, trigger Node, stdout io.Reader, stderr io.Reader) (Result, error)
}

type Result struct {
    Nodes    []Node     // New or updated nodes
    Edges    []Edge     // Relationships to create
    Findings []Finding  // Vulns / observations
}
```

### 3.3 The YAML invocation schema

```yaml
enrichers:
  - name: nmap_ssh                    # unique, used as enriched_by stamp
    parser: nmap_xml                  # matches parser registry key
    subscribes:
      node_type: Service
      predicate: "product = 'ssh' AND in_scope = true"
    command:
      bin: nmap
      args:
        - "-sV"
        - "-Pn"
        - "--script"
        - "ssh-auth-methods,ssh2-enum-algos,ssh-hostkey"
        - "-p"
        - "{{.Node.port}}"
        - "-oX"
        - "-"
        - "{{.Node.ip}}"
      timeout: 5m
    concurrency: 4
    enabled: true
```

### 3.4 Template variables available in args

| Variable | Source | Example |
|---|---|---|
| `{{.Node.<field>}}` | Properties on the triggering node | `{{.Node.fqdn}}`, `{{.Node.ip}}`, `{{.Node.port}}` |
| `{{.Edge.<field>}}` | Properties on the matched edge (for compound patterns) | `{{.Edge.resolved_ip}}` for DNS-first httpx |
| `{{.ScanRun.id}}` | Current scan run identifier | for tool output directories |
| `{{.Config.<key>}}` | Values from `asm.yaml` global config | `{{.Config.resolvers_file}}` |

Template expansion happens once per dispatch, validated at startup against synthetic nodes to catch typos before first run.

### 3.5 Predicate language

Predicates are Cypher `WHERE` fragments appended to the engine's dispatch query. Full Cypher power, no custom DSL. Validation at config load refuses startup if any predicate fails to parse.

```yaml
# Simple property filter
predicate: "product = 'ssh' AND in_scope = true"

# Edge existence check (DNS-first rule for HTTP)
predicate: |
  in_scope = true AND EXISTS {
    MATCH (this)-[:RESOLVES_TO]->(:IP)-[:HAS_SERVICE]->(svc:Service)
    WHERE svc.product IN ['http', 'https']
  }
```

---

## 4. Neo4j Schema

### 4.1 Node types

| Label | Primary key | Purpose |
|---|---|---|
| `Domain` | `fqdn` | Root domain (seed input) |
| `Subdomain` | `fqdn` | Resolved or discovered hostname. DNS-first anchor for web enrichment. |
| `IP` | `address` | IPv4/IPv6 with ASN, org, geo from ipintel |
| `Service` | `ip_port` (e.g. `"1.2.3.4:443"`) | Port with detected product/version |
| `Certificate` | `sha256` | TLS certificate. SANs feed back to `Subdomain`. |
| `URL` | `url` | HTTP(S) endpoint discovered by httpx/webscope |
| `Technology` | `(name, version)` | Detected tech stack. Drives nuclei tag filtering. |
| `JSFile` | `(url, sha256)` | JavaScript file. Composite key catches drift. |
| `Endpoint` | `(url, method, path)` | API endpoint from crawling or JS analysis |
| `Form` | `(url, action)` | HTML form |
| `Finding` | `id` (uuid) | Polymorphic — `type` property distinguishes variants |
| `ScanRun` | `id` (uuid) | Provenance tracking |

### 4.2 Base properties on every node

```go
type BaseNode struct {
    FirstSeen       time.Time
    LastSeen        time.Time
    DiscoveryDepth  int         // 0 for seeds, parent+1 for discovered
    ScanRunID       string
    EnrichedBy      []string    // ["subscope", "dnsx", "httpx"] — the cycle brake
    InScope         bool        // Cached scope result
}
```

The `EnrichedBy` list is the cycle brake. Dispatcher check:
```cypher
WHERE NOT $enricher_name IN node.enriched_by
```

### 4.3 Relationships

| Edge | From → To | Properties |
|---|---|---|
| `HAS` | `Domain` → `Subdomain` | |
| `CNAME` | `Subdomain` → `Subdomain` | chain position |
| `RESOLVES_TO` | `Subdomain` → `IP` | `record_type`, `ttl` |
| `HAS_SERVICE` | `IP` → `Service` | |
| `PRESENTS` | `Service` → `Certificate` | |
| `SERVES` | `Subdomain` → `URL` | **`port`, `scheme`, `resolved_ip`** (DNS-first hint) |
| `RUNS` | `URL` → `Technology` | `confidence` |
| `LOADS` | `URL` → `JSFile` | |
| `EXPOSES` | `URL` → `Endpoint` | |
| `CONTAINS` | `URL` → `Form` | |
| `HAS_FINDING` | *any* → `Finding` | |
| `DISCOVERED_BY` | *any* → `ScanRun` | `timestamp` |

The `SERVES.resolved_ip` property is load-bearing: web enrichers use it to build `--resolve host:port:ip` for vhost-correct requests.

### 4.4 Schema initialization (Cypher)

```cypher
CREATE CONSTRAINT domain_fqdn IF NOT EXISTS FOR (n:Domain) REQUIRE n.fqdn IS UNIQUE;
CREATE CONSTRAINT subdomain_fqdn IF NOT EXISTS FOR (n:Subdomain) REQUIRE n.fqdn IS UNIQUE;
CREATE CONSTRAINT ip_address IF NOT EXISTS FOR (n:IP) REQUIRE n.address IS UNIQUE;
CREATE CONSTRAINT service_key IF NOT EXISTS FOR (n:Service) REQUIRE n.ip_port IS UNIQUE;
CREATE CONSTRAINT cert_sha IF NOT EXISTS FOR (n:Certificate) REQUIRE n.sha256 IS UNIQUE;
CREATE CONSTRAINT url_unique IF NOT EXISTS FOR (n:URL) REQUIRE n.url IS UNIQUE;
CREATE CONSTRAINT tech_key IF NOT EXISTS FOR (n:Technology) REQUIRE (n.name, n.version) IS UNIQUE;
CREATE CONSTRAINT js_key IF NOT EXISTS FOR (n:JSFile) REQUIRE (n.url, n.sha256) IS UNIQUE;
CREATE CONSTRAINT finding_id IF NOT EXISTS FOR (n:Finding) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT scanrun_id IF NOT EXISTS FOR (n:ScanRun) REQUIRE n.id IS UNIQUE;

CREATE INDEX subdomain_status IF NOT EXISTS FOR (n:Subdomain) ON (n.status);
CREATE INDEX service_product IF NOT EXISTS FOR (n:Service) ON (n.product);
CREATE INDEX url_status IF NOT EXISTS FOR (n:URL) ON (n.status_code);
CREATE INDEX finding_severity IF NOT EXISTS FOR (n:Finding) ON (n.severity);
CREATE INDEX finding_tool IF NOT EXISTS FOR (n:Finding) ON (n.tool);
CREATE INDEX node_inscope IF NOT EXISTS FOR (n:Subdomain) ON (n.in_scope);
```

### 4.5 Finding model

Polymorphic — one label, `type` property distinguishes variants. Rooted on whichever node it belongs to:
- Web vulns → `URL`
- Network vulns → `Service`
- Secrets → `JSFile` or `URL`
- Takeovers → `Subdomain`
- Cert issues → `Certificate`

```go
type Finding struct {
    ID          string
    Type        string                 // "ssh-weak-kex", "open-redirect", "exposed-dotgit"
    Title       string
    Severity    string                 // info|low|medium|high|critical
    Confidence  string                 // tentative|firm|confirmed
    Tool        string                 // which enricher produced this
    CVE         []string
    CWE         []string
    Evidence    map[string]interface{} // tool-specific payload
    FirstSeen   time.Time
    LastSeen    time.Time
}
```

---

## 5. Parser Taxonomy

The 18 output shapes that cover every tool in Phase 1. Each is one file under `internal/parsers/`.

| Parser | Emits | Complexity | Tools handled |
|---|---|---|---|
| `hostname_list` | `Subdomain` nodes | trivial | subfinder, assetfinder, amass, crt.sh, dnstwist, theHarvester |
| `dns_resolver` | `Subdomain` + `IP` + `RESOLVES_TO` | small | dnsx, puredns, shuffledns, massdns |
| `port_scan` | `Service` nodes | small | naabu, masscan, rustscan |
| `nmap_xml` | `Service` props + `Finding` from NSE | medium | nmap (all script variants) |
| `http_probe` | `URL` + `Technology` | small | httpx, webanalyze |
| `url_list` | `URL` nodes | trivial | gau, waybackurls, katana, hakrawler, gospider, feroxbuster, ffuf |
| `tls_audit` | `Certificate` + cert `Finding` | medium | tlsx, testssl.sh, sslyze |
| `nuclei_jsonl` | `Finding` (rooted on trigger) | medium | nuclei (all template sets) |
| `secret_scanner` | `Finding{type: secret}` | small | trufflehog, gitleaks |
| `smb_enum` | `Subdomain` leaks + `Finding` | medium | enum4linux-ng, netexec |
| `screenshot` | `URL.screenshot_path` property | trivial | gowitness |
| `param_discovery` | `Endpoint.params` updates | small | arjun, linkfinder |
| `web_vuln_generic` | `Finding` rooted on `URL` | medium | nikto, wapiti, dalfox, corsy |
| `subscope_json` | Rich: `Subdomain` + `IP` + cloud | medium | subscope (custom) |
| `webscope_jsonl` | `URL`, `Endpoint`, `Form`, `JSFile`, `Finding` | large | webscope (custom) |
| `jsrecon_json` | `Endpoint`, `Subdomain` refs, drift `Finding` | medium | jsRecon (custom) |
| `proxyhawk_json` | `Finding{ssrf, open-redirect, ...}` | small | proxyhawk (custom) |
| `ipintel_json` | `IP` property updates (ASN, org, geo) | trivial | ipintel (custom) |

18 parsers for Phase 1. Every tool from the original pipeline YAML that's still in scope has a home.

---

## 6. Phase 1 Tool Roster

Single source of truth for what's working versus what's stubbed. Every tool below has an entry in `configs/enrichers.yaml`; the status reflects `enabled:` state.

### 6.1 Active in Phase 1 — 18 tools

Working parsers AND enabled YAML entries. These ship with Phase 1.

| Tool | Parser | Role | Notes |
|---|---|---|---|
| **subscope** | `subscope_json` | DNS enum on `Domain` | Custom, primary entry point |
| **ipintel** | `ipintel_json` | IP metadata on `IP` | Custom, property enrichment |
| **webscope** | `webscope_jsonl` | Crawl on `URL` | Custom, streaming JSONL |
| **jsRecon** | `jsrecon_json` | JS analysis on `JSFile` | Custom, may need output format changes |
| **proxyhawk** | `proxyhawk_json` | SSRF/redirect on `URL` | Custom |
| **dnsx** | `dns_resolver` | Resolution on new `Subdomain` | ProjectDiscovery, JSON output |
| **naabu** | `port_scan` | Port discovery on `IP` | ProjectDiscovery, JSON output |
| **nmap** | `nmap_xml` | Service-specific NSE on `Service` | Multiple YAML entries (ssh, smb, tls, http) |
| **httpx** | `http_probe` | HTTP probe on `Subdomain`+http `Service` | DNS-first rule enforced |
| **tlsx** | `tls_audit` | Cert grab on TLS `Service` | SAN extraction → cycle |
| **nuclei** | `nuclei_jsonl` | Template scans | Multiple YAML entries (takeover, network, web-vuln, cves) |
| **subfinder** | `hostname_list` | Exemplar for hostname_list shape | Enables amass/assetfinder later via YAML |
| **gau** | `url_list` | Historical URLs on `Subdomain` | Picked over waybackurls (more sources) |
| **trufflehog** | `secret_scanner` | Secret scan on exposed `.git`/`.env` | Picked over gitleaks (broader source support) |
| **katana** | `url_list` | Crawl on `URL` (complement to webscope) | |
| **subzy** | `nuclei_jsonl`* | Takeover check on `Subdomain` with dangling CNAME | *Uses nuclei's subzy-compatible templates |
| **gowitness** | `screenshot` | Screenshot on `URL` | Populates `URL.screenshot_path` |
| **arjun** | `param_discovery` | Param fuzz on `URL` with forms | |

### 6.2 Stubbed in Phase 1 — 30 tools

YAML entries with `enabled: false` AND a parser assigned. Enabling any of them is a one-line YAML change — no Go code required.

| Tool | Parser (already exists) | Why deferred |
|---|---|---|
| amass | `hostname_list` | subfinder covers the exemplar; amass intel mode adds overlap |
| assetfinder | `hostname_list` | Duplicate of subfinder coverage |
| crt.sh | `hostname_list` | Covered via subfinder's CT sources |
| theHarvester | `hostname_list` | OSINT aggregator — lower marginal value given subscope |
| dnstwist | `hostname_list` | Typosquat generator — Phase 2 OSINT layer |
| puredns | `dns_resolver` | dnsx handles resolution adequately |
| shuffledns | `dns_resolver` | subscope already invokes shuffledns internally |
| massdns | `dns_resolver` | Redundant with dnsx + shuffledns |
| alterx | `hostname_list` | Permutation generator — subscope invokes internally |
| masscan | `port_scan` | naabu covers the exemplar |
| rustscan | `port_scan` | Duplicate of naabu |
| testssl.sh | `tls_audit` | tlsx covers the exemplar; testssl is slower |
| sslyze | `tls_audit` | Duplicate of tlsx coverage |
| openssl | `tls_audit` | Primitive — used internally, not as enricher |
| waybackurls | `url_list` | gau covers the exemplar |
| hakrawler | `url_list` | katana covers the exemplar |
| gospider | `url_list` | Duplicate crawler |
| feroxbuster | `url_list` | Content bruteforce — webscope covers the common case |
| ffuf | `url_list` | Fuzzer — needs dedicated wordlist management |
| webanalyze | `http_probe` | httpx `-tech-detect` covers common case |
| linkfinder | `param_discovery` | webscope + jsRecon cover JS endpoint extraction |
| kiterunner | `url_list` | API discovery — Phase 2 API-specific layer |
| getJS | `url_list` | webscope already extracts JS references |
| gitleaks | `secret_scanner` | trufflehog covers the exemplar |
| enum4linux-ng | `smb_enum` | Defer until SMB findings become a priority |
| netexec | `smb_enum` | Active cred check — needs careful scope gating |
| nikto | `web_vuln_generic` | nuclei covers the common case |
| wapiti | `web_vuln_generic` | Duplicate of nuclei coverage |
| dalfox | `web_vuln_generic` | XSS-specific — Phase 2 targeted fuzzing |
| corsy | `web_vuln_generic` | CORS — covered by nuclei templates |

### 6.3 Explicitly removed from scope — 17 tools

These were in the original pipeline YAML but are not part of Phase 1 at all — no parser, no YAML entry, not tracked in `enrichers.yaml`. They belong to other phases or other concerns entirely.

| Category | Tools | Disposition |
|---|---|---|
| **API-based OSINT** | shodan, censys, securitytrails, dehashed, postleaks, bgp.he.net, searchsploit | Removed. Different execution model (HTTP client, not subprocess). Revisit if/when we add an `APIClient` runner. |
| **Interactive / stateful scanners** | zap, sqlmap | Removed. Require session management that doesn't fit the parse-stdout model. Phase 3 at earliest. |
| **Cloud & supply chain** | cloud_enum, s3scanner, trivy, grype, syft, dependency-track | Removed. Separate trust model (needs cloud creds). Phase 3 cloud stage. |
| **Finding sinks** | defectdojo, faraday, jira, epss_feed, cisa_kev_catalog | Removed from enrichers. These consume findings, not produce graph data. Belong in Phase 2 `FindingSink` interface. |

**Totals: 65 tools in the original YAML → 18 active, 30 stubbed, 17 removed.**

Every tool from the original pipeline YAML is accounted for in one of those three buckets.

---

## 7. Enricher → Node Subscription Map (Active Tools)

The Phase 1 wiring. Multiple YAML entries can share one parser — nmap is the clearest example with four variants.

| Trigger node | Predicate | YAML entry | Parser | Produces |
|---|---|---|---|---|
| `Domain` | `in_scope=true` | `subscope_domain` | `subscope_json` | `Subdomain`, `IP`, cloud tags |
| `Domain` | `in_scope=true` | `subfinder_domain` | `hostname_list` | `Subdomain` |
| `Subdomain` (new) | `status='discovered'` | `dnsx_resolve` | `dns_resolver` | `IP`, `RESOLVES_TO` |
| `IP` (new) | `in_scope=true` | `ipintel_enrich` | `ipintel_json` | `IP` property update |
| `IP` | `in_scope=true` | `naabu_scan` | `port_scan` | `Service` |
| `Service` | `product='ssh'` | `nmap_ssh` | `nmap_xml` | `Finding` (weak algos) |
| `Service` | `product='smb'` | `nmap_smb` | `nmap_xml` | `Finding`, `Subdomain` leaks |
| `Service` | `product='http' OR product='https'` | `nmap_http_scripts` | `nmap_xml` | `Finding` (http-* NSE) |
| `Service` | `tls=true` | `tlsx_cert` | `tls_audit` | `Certificate` (SANs → cycle) |
| `Service` | `tls=true` | `nmap_ssl_enum` | `nmap_xml` | `Finding` (cipher issues) |
| `Subdomain`+`Service{http}` | DNS-first predicate | `httpx_probe` | `http_probe` | `URL`, `Technology` |
| `Subdomain` | `status='resolved' AND has_dangling_cname=true` | `subzy_takeover` | `nuclei_jsonl` | `Finding{takeover}` |
| `URL` | `status_code BETWEEN 200 AND 399` | `webscope_crawl` | `webscope_jsonl` | `URL`, `Endpoint`, `Form`, `JSFile`, `Finding` |
| `URL` | `status_code = 200` | `katana_crawl` | `url_list` | `URL` |
| `URL` | `status_code = 200` | `gau_historical` | `url_list` | `URL` |
| `URL` | `status_code = 200` | `gowitness_shot` | `screenshot` | `URL.screenshot_path` |
| `URL` | `has_forms=true OR has_params=true` | `arjun_params` | `param_discovery` | `Endpoint` params |
| `URL` | `has_params=true OR has_redirects=true` | `proxyhawk_probe` | `proxyhawk_json` | `Finding{ssrf,redirect}` |
| `URL` | `path MATCHES '.*\\.(git|env|DS_Store).*'` | `trufflehog_exposed` | `secret_scanner` | `Finding{secret}` |
| `JSFile` | new or hash changed | `jsrecon_analyze` | `jsrecon_json` | `Endpoint`, `Subdomain`, drift `Finding` |
| `URL`+`Technology` | tech tagged | `nuclei_tech` | `nuclei_jsonl` | `Finding{cve,misconfig}` |
| `Service` | `product NOT IN ['http','https']` | `nuclei_network` | `nuclei_jsonl` | `Finding` (network templates) |

22 active YAML entries across 18 tools (nmap and nuclei each get multiple invocations).

---

## 8. Controlling the Explosion

Four layered mechanisms. All must be in place before the first real scan.

### 8.1 Global concurrency budget

Single worker pool, `runtime.NumCPU() * 2` by default. Every enricher job goes through it.

### 8.2 Per-enricher semaphores

Each YAML entry declares `concurrency:`. Prevents one noisy tool from starving others:

```yaml
# Representative values
subscope:  2    # heavy, network-bound
nmap:      4    # heavy, network-bound
webscope:  8    # moderate
nuclei:    2    # very heavy, many templates
httpx:    16    # light, fast
jsrecon:  16    # cheap, static analysis
dnsx:     32    # trivial
```

### 8.3 Scope guard on every upsert

`scope.Validate(node)` runs before any node enters the graph:
- Domain/subdomain against `in_scope_domains` (suffix match)
- IP against `in_scope_cidr`
- ASN against `in_scope_asn`

Out-of-scope nodes become `Finding{type: "out-of-scope-asset"}` on the parent and **do not trigger further enrichment**. Single most important loop brake.

### 8.4 Iteration + depth budgets

- `max_iterations` (default 5) — caps dispatcher passes
- `max_discovery_depth` (default 6) — caps chain length (seed=0, each hop +1)

Together these give a hard worst-case ceiling you can reason about before launching a scan.

---

## 9. DNS-First Rule for HTTP

Implementation detail for the concern you flagged.

**`httpx` and `webscope` subscribe to `Subdomain` nodes with an http/https `Service` edge, not to bare `IP` nodes.**

Dispatch query:

```cypher
MATCH (s:Subdomain)-[:RESOLVES_TO]->(i:IP)-[:HAS_SERVICE]->(svc:Service)
WHERE svc.product IN ['http', 'https']
  AND s.in_scope = true
  AND NOT 'httpx_probe' IN s.enriched_by
RETURN s, i.address AS resolved_ip, svc.port AS port, svc.product AS scheme
```

The enricher invokes `httpx --resolve hostname:port:ip` to guarantee vhost-correct requests:

```yaml
command:
  bin: httpx
  args:
    - "-u"
    - "{{.Node.fqdn}}"
    - "-resolve"
    - "{{.Node.fqdn}}:{{.Edge.port}}:{{.Edge.resolved_ip}}"
    - "-json"
    - "-tech-detect"
    - "-title"
    - "-status-code"
```

Bare IPs with :443 open and no hostname get `Finding{type: "http-service-no-hostname"}` logged but no crawl. Config flag `ip_direct_http: false` is the default override.

---

## 10. Phase 1 Build Order

Concrete sequence. Each step produces something runnable before moving on.

1. **Graph + engine skeleton** — Neo4j connection, schema init, Parser interface, registry, worker pool, scope validator, dedup, template engine. Hand-written fake parser proves the loop. *Commit: `graph-alive`*
2. **Config loader + YAML validator** — Load `enrichers.yaml`, validate predicates against Neo4j, validate templates against synthetic nodes, refuse startup on any error. *Commit: `config-validated`*
3. **Custom tools first** — subscope + ipintel. Simplest custom parsers, validates the loop without HTTP complexity. *Commit: `dns-walking`*
4. **Port discovery** — naabu + nmap (ssh variant first). Creates `Service` nodes, drives service branching. *Commit: `services-mapped`*
5. **TLS cycle** — tlsx. SANs feed back to `Subdomain`. **First real cycle appears here.** *Commit: `cycles-working`*
6. **Web probe** — httpx with DNS-first rule. `Technology` nodes for nuclei filtering. *Commit: `web-discovered`*
7. **Web enrichment** — webscope + jsRecon. Expect the first surge of new nodes; scope/budget guards earn their keep. *Commit: `web-enriched`*
8. **Secondary web tools** — katana, gau, gowitness, arjun, trufflehog. All share existing parsers, mostly YAML work. *Commit: `web-complete`*
9. **Vuln probing** — proxyhawk + nuclei (all variants). *Commit: `vulns-detected`*
10. **Takeover + remaining nmap variants** — subzy, nmap_smb, nmap_http, nmap_ssl_enum. *Commit: `phase-1-complete`*

Target state: domain in → enriched graph + findings in Neo4j → JSON export. 18 working tools, 30 stubbed, 17 removed from scope.

---

## 11. Phase 2 Hooks (Design Now, Build Later)

Cheap things to do in Phase 1 to avoid rewrite pain:

- **`FindingSink` interface** with `JSONFileSink` impl. Phase 2 adds `LLMValidatorSink` that wraps another sink.
- **Runtime-mutable parser registry.** Phase 2's LLM can construct ad-hoc enricher entries and hand them to the engine.
- **Structured logging via `slog`** on every parser invocation. Phase 2's LLM audit trail needs this anyway.

Do not build LLM integration yet. Do not design prompts. Just leave the seams.

---

## 12. Explicitly Out of Scope

Listed to prevent creep:

- **Distributed workers** — single-process + Neo4j is sufficient for Phase 1
- **Web UI** — Neo4j Browser + Cypher queries cover Phase 1
- **Metrics/Prometheus** — `slog` is enough until real need
- **API-based OSINT tools** — shodan, censys, securitytrails, dehashed, postleaks, bgp.he.net, searchsploit (need APIClient runner model — not Phase 1)
- **Interactive scanners** — ZAP, sqlmap (need session management — Phase 3)
- **Cloud & supply chain stage** — cloud_enum, s3scanner, trivy, grype, syft, dependency-track (Phase 3)
- **Finding sinks** — defectdojo, faraday, jira (Phase 2 `FindingSink`)
- **Enrichment feeds** — epss_feed, cisa_kev_catalog (Phase 2 triage-time decoration)
- **LLM validation/reporting** — Phase 2
- **Continuous monitoring / scheduled re-runs** — Phase 3

---

## 13. Open Questions

1. **jsRecon output format** — may need changes to emit structured JSON with file hash + extracted data in one blob. Confirm when wiring enricher.
2. **Custom tools as libraries vs subprocesses** — all five are Go. If importable as packages rather than exec'd, we save subprocess overhead and get typed errors. Evaluate per-tool during build order step 3.
3. **Neo4j deployment** — default assumption: external Neo4j at `bolt://localhost:7687`. Confirm.
4. **Scope definition format** — default: single `asm.yaml` block, reloadable between runs.
5. **`Endpoint` and `Form` as separate nodes vs properties on `URL`** — current plan is separate nodes (individually actionable for later fuzzing). Revisit if graph gets unwieldy.
6. **gau vs waybackurls, trufflehog vs gitleaks** — picked gau and trufflehog as exemplars. Confirm or swap.

---

## 14. Next Steps

1. Draft `internal/graph/schema.go` — node struct definitions, constraint init, generic upsert (~150 lines)
2. Draft `internal/graph/graph.go` — driver, session management, transaction helpers (~100 lines)
3. Draft `internal/parsers/parser.go` — Parser interface, registry (~80 lines)
4. Draft `internal/engine/engine.go` — dispatcher, worker pool, budget enforcement (~200 lines)
5. Draft `internal/engine/template.go` — text/template expansion with validation (~80 lines)
6. Draft `configs/enrichers.yaml` — 48 tool entries (18 enabled, 30 disabled)
7. Wire a synthetic test parser to prove the loop end-to-end

Target: ~650 lines of commented Go + complete `enrichers.yaml` before touching any real tool. Then subscope first.
