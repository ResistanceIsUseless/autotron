# Autotron

Autotron is a graph-driven attack-surface management and recon orchestration platform.

It runs a configurable enrichment pipeline over discovered assets, stores relationships in Neo4j, and produces triage-focused findings and reports.

## What it does

- Seeds scans from one or more target domains.
- Expands surface through typed nodes (Domain, Subdomain, IP, Service, URL, Endpoint, JSFile, Form, ScanRun).
- Executes enrichers (external tools/helpers) based on node type + predicates.
- Parses tool output into normalized nodes, edges, and findings.
- Enforces scope/depth controls and dedup across pipeline stages.
- Generates top-findings output and per-host reports (`text`, `json`, `markdown`).

## High-level flow

1. `Domain` seeds are written to Neo4j.
2. Enabled enrichers subscribe to matching pending nodes.
3. Tool output is parsed into graph updates.
4. New graph artifacts trigger additional enrichers until convergence/budget limits.
5. Findings are queryable through CLI reports and web UI.

## Repository layout

- `cmd/asm/` - main CLI (`scan`, `validate`, `report`, `webui`)
- `internal/engine/` - orchestration, dispatch, scope/depth controls
- `internal/graph/` - Neo4j schema + query/write logic
- `internal/parsers/` - parser implementations and contracts
- `configs/asm.yaml` - global config (Neo4j, scope, budget, scan settings)
- `configs/enrichers.yaml` - enricher catalog and runtime wiring
- `docs/` - setup and workflow docs for specific helper modules

## Feature matrix

Current default profile (`configs/enrichers.yaml`): `18 / 82` enrichers enabled.

Enabled by default (core pipeline):

- Surface expansion: `subscope_domain`, `subfinder_domain`, `dnsx_resolve`, `naabu_scan`
- Service enrichment: `nmap_ssh`, `nmap_smb`, `nmap_http_scripts`, `nmap_ssl_enum`, `tlsx_cert`
- Web discovery: `httpx_probe`, `webscope_crawl`, `katana_crawl`, `gau_historical`
- Security signal generation: `subzy_takeover`, `trufflehog_exposed`, `jsrecon_analyze`, `nuclei_tech`, `nuclei_network`

Optional modules (disabled by default, enable in stages):

- Passive intel providers: Google/Bing/Yandex dorking, Shodan/FOFA host passive, GitHub/GitLab repo intel
- Cloud and exposure posture: S3/GCS/Azure bucket checks, mail posture (MX/SPF/DMARC)
- API and auth surface: OpenAPI/GraphQL/authz heuristics, OIDC/OAuth/SAML checks
- Advanced web classes: desync/cache-poison/WAF diff plus SSRF/IDOR/CSRF heuristic mappings
- Mobile and visual workflows: APK/IPA artifact endpoint extraction, screenshot clustering
- Drift intelligence: delta new-exposure/new-findings/surface-regression checks

### Suggested enablement profiles

`passive-plus` (low-noise, lowest risk):

- `google_dork_passive`, `bing_dork_passive`, `yandex_dork_passive`
- `url_shortener_search_passive`
- `shodan_host_passive`, `censys_host_passive`, `fofa_host_passive`
- `github_code_search_passive`, `gitlab_code_search_passive`
- `s3_bucket_enum`, `gcs_bucket_enum`, `azure_blob_enum`
- `mx_posture_audit`, `spf_dkim_dmarc_audit`

`auth-api` (focused app posture):

- `openapi_discovery`, `graphql_surface`, `api_authz_heuristics`
- `oidc_discovery`, `oauth_misconfig_probe`, `saml_metadata_enum`

`advanced-web` (higher signal variance):

- `http_desync_probe`, `cache_poison_probe`, `waf_diff_probe`
- `ssrf_gadget_discovery`, `idor_candidate_mapper`, `csrf_policy_audit`
- keep concurrency low and scope strict

To view the exact active set at runtime:

```bash
go run ./cmd/asm validate
```

## Prerequisites

- Go `1.24+`
- Neo4j reachable at your configured URI
- External tools/helpers referenced by enabled enrichers

## Install (primary)

Use `go install` as the default install method:

```bash
go install github.com/ResistanceIsUseless/autotron/cmd/asm@latest
```

Then verify:

```bash
asm --help
```

If your `GOBIN` is not on `PATH`, add it first (commonly `$(go env GOPATH)/bin` or `$(go env GOBIN)`).

## Start dependencies

### 1) Start Neo4j

Default Autotron config expects:

- URI: `bolt://localhost:7687`
- Username: `neo4j`
- Password: `changeme`

Run Neo4j with Docker:

```bash
docker run -d --name autotron-neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/changeme \
  neo4j:5
```

### 2) Start jsRecon API

Autotron default expects jsRecon at `http://localhost:37232`.

From a local `jsRecon` checkout:

```bash
cd jsRecon
npm install
npm start
```

Or with Docker:

```bash
docker build -t jsrecon:latest ./jsRecon
docker run --rm -p 37232:37232 jsrecon:latest serve --port 37232
```

If you use different ports/hosts, update `configs/asm.yaml` (`neo4j.*` and `scan.jsrecon_base`).

## Quick start

1. Configure Neo4j and scope in `configs/asm.yaml`.
2. Review enabled enrichers in `configs/enrichers.yaml`.
3. Validate wiring:

```bash
go run ./cmd/asm validate
```

4. Run a scan:

```bash
go run ./cmd/asm scan -d example.com
```

5. Get findings summary:

```bash
go run ./cmd/asm report --top 25
```

6. Generate host markdown report:

```bash
go run ./cmd/asm report --host api.example.com --format markdown --save
```

7. Start web UI:

```bash
go run ./cmd/asm webui --addr :8090
```

8. Preview or apply enricher profiles:

```bash
# list profiles
asm profile --list

# dry-run preview
asm profile --name passive-plus

# apply profile changes to configs/enrichers.yaml
asm profile --name passive-plus --apply

# disable a profile set
asm profile --name passive-plus --apply --disable
```

## Build

```bash
go build -o asm ./cmd/asm
./asm validate
```

## Development checks

```bash
go test ./...
go vet ./...
go run ./cmd/asm validate
```

## Notable docs

- `asm-pipeline-plan.md`
- `docs/report_example.md`
- `docs/missing-checks-implementation-backlog.md`
- `docs/api-surface-setup.md`
- `docs/auth-surface-setup.md`
- `docs/cloud-bucket-check-setup.md`
- `docs/mail-posture-setup.md`
- `docs/web-advanced-setup.md`

## Safety and usage

Only scan assets you are explicitly authorized to test. Keep scope constraints strict, and enable high-impact enrichers in stages.
