# Missing Checks Implementation Backlog

This is a ready-to-execute build plan for the checks currently missing from Autotron.

Scope assumptions:
- Keep strict scope controls and passive-first defaults.
- Add new enrichers disabled by default until tooling/API keys are configured.
- Reuse existing parsers where possible; add targeted parsers only where output shape differs.

---

## Priority 0 (ship first)

### 1) Search / Dorking Intelligence

- **Enrichers**
  - `google_dork_passive`
  - `bing_dork_passive`
  - `yandex_dork_passive`
- **Subscribe**
  - `node_type: Domain`
  - `predicate: "n.in_scope = true"`
- **Parser**
  - New: `search_dork_json`
- **Output shape**
  - Nodes: `URL` (if in-scope host)
  - Findings: `indexed-sensitive-path`, `indexed-admin-surface`, `indexed-exposed-config`
- **Graph fields**
  - `Finding.evidence_json`: query, engine, matched_url, snippet, rank
  - `Finding.type`: `dork-<class>`

### 2) Internet-Wide Passive Exposure

- **Enrichers**
  - `shodan_host_passive`
  - `censys_host_passive`
  - `fofa_host_passive`
- **Subscribe**
  - `node_type: IP`
  - `predicate: "n.in_scope = true"`
- **Parser**
  - New: `exposure_passive_json`
- **Output shape**
  - Nodes: `Service` (observed banners/ports)
  - Findings: `exposed-service-passive`, `known-banner-risk`, `internet-exposed-admin`

### 3) Cloud Storage Exposure

- **Enrichers**
  - `s3_bucket_enum`
  - `gcs_bucket_enum`
  - `azure_blob_enum`
- **Subscribe**
  - `node_type: Domain`
  - `predicate: "n.in_scope = true"`
- **Parser**
  - New: `cloud_bucket_json`
- **Output shape**
  - Findings: `public-bucket-listing`, `public-object-read`, `bucket-takeover-candidate`
  - Evidence: provider, bucket, acl, sample object paths

### 4) Code / Repo Leak Discovery

- **Enrichers**
  - `github_code_search_passive`
  - `gitlab_code_search_passive`
- **Subscribe**
  - `node_type: Domain`
  - `predicate: "n.in_scope = true"`
- **Parser**
  - New: `repo_leak_json`
- **Output shape**
  - Findings: `repo-secret-leak`, `repo-internal-host-leak`, `repo-hardcoded-token`
  - Evidence: repo, file path, line, matched pattern

---

## Priority 1 (second wave)

### 5) API Security Dedicated Checks

- **Enrichers**
  - `openapi_discovery`
  - `graphql_surface`
  - `api_authz_heuristics`
- **Subscribe**
  - `node_type: URL`
  - `predicate: "n.status_code = 200"`
- **Parser**
  - New: `api_surface_json`
- **Output shape**
  - Nodes: `Endpoint`
  - Findings: `openapi-exposed`, `graphql-introspection-enabled`, `bola-candidate`

### 6) Auth / SSO Misconfiguration Checks

- **Enrichers**
  - `oidc_discovery`
  - `oauth_misconfig_probe`
  - `saml_metadata_enum`
- **Subscribe**
  - `node_type: URL`
  - `predicate: "n.status_code = 200"`
- **Parser**
  - New: `auth_surface_json`
- **Output shape**
  - Findings: `oidc-weak-config`, `oauth-open-redirect-candidate`, `jwks-mismatch`

### 7) Advanced Web Class Coverage

- **Enrichers**
  - `ssrf_gadget_discovery`
  - `idor_candidate_mapper`
  - `csrf_policy_audit`
- **Subscribe**
  - `node_type: Endpoint`
  - `predicate: "n.in_scope = true"`
- **Parser**
  - Reuse `web_vuln_generic` initially; add `logic_vuln_json` later if needed

### 8) Screenshot + Visual Clustering

- **Enrichers**
  - enable `gowitness_shot`
  - add `screenshot_cluster`
- **Subscribe**
  - `node_type: URL`
  - `predicate: "n.status_code = 200"`
- **Parser**
  - Reuse `screenshot`
  - New optional parser: `visual_cluster_json`
- **Output shape**
  - Findings: `exposed-login-panel`, `admin-ui-detected`, `known-product-panel`

---

## Priority 2 (elite depth)

### 9) HTTP Desync / Smuggling / Cache Poisoning

- **Enrichers**
  - `http_desync_probe`
  - `cache_poison_probe`
  - `waf_diff_probe`
- **Subscribe**
  - `node_type: URL`
  - `predicate: "n.status_code = 200"`
- **Parser**
  - New: `http_advanced_vuln_json`
- **Output shape**
  - Findings: `request-smuggling-candidate`, `cache-poisoning-candidate`, `waf-bypass-diff`

### 10) Mobile Artifact Recon

- **Enrichers**
  - `apk_endpoint_extract`
  - `ipa_endpoint_extract`
- **Subscribe**
  - `node_type: URL`
  - `predicate: "n.path =~ '.*\\.(apk|ipa)$'"`
- **Parser**
  - New: `mobile_artifact_json`

### 11) Email / MX Security Checks

- **Enrichers**
  - `mx_posture_audit`
  - `spf_dkim_dmarc_audit`
  - `smtp_open_relay_probe`
- **Subscribe**
  - `node_type: Domain`
  - `predicate: "n.in_scope = true"`
- **Parser**
  - New: `mail_posture_json`
- **Output shape**
  - Findings: `missing-dmarc`, `weak-spf`, `open-relay-risk`

### 12) Continuous Drift / Delta Intelligence

- **Enrichers**
  - `delta_new_exposure`
  - `delta_new_findings`
  - `delta_surface_regression`
- **Subscribe**
  - `node_type: ScanRun`
  - `predicate: "true"`
- **Parser**
  - New: `delta_report_json`

---

## Existing but Disabled (enable in stages)

- Discovery: `amass_enum`, `assetfinder_enum`, `crtsh_enum`, `theharvester_enum`, `dnstwist_enum`, `alterx_permute`
- DNS resolvers: `puredns_resolve`, `shuffledns_resolve`, `massdns_resolve`
- Port/TLS: `masscan_scan`, `rustscan_scan`, `testssl_audit`, `sslyze_audit`, `openssl_cert`
- Crawl/fuzz: `waybackurls_hist`, `hakrawler_crawl`, `gospider_crawl`, `feroxbuster_brute`, `ffuf_fuzz`
- Web/API/JS: `webanalyze_tech`, `linkfinder_js`, `kiterunner_api`, `getjs_extract`
- Vuln/secret: `gitleaks_scan`, `nikto_scan`, `wapiti_scan`, `dalfox_xss`, `corsy_cors`
- Visual/SMB: `gowitness_shot`, `enum4linux_smb`, `netexec_smb`

Enablement rule:
- Start with passive-only + low-risk active checks.
- Turn on high-noise fuzzers only behind budget/scope gates.

---

## New Parsers to Add (exact list)

- `search_dork_json`
- `exposure_passive_json`
- `cloud_bucket_json`
- `repo_leak_json`
- `api_surface_json`
- `auth_surface_json`
- `http_advanced_vuln_json`
- `mobile_artifact_json`
- `mail_posture_json`
- `delta_report_json`

---

## YAML Entry Naming (recommended)

- Keep names machine-sortable and grouped:
  - `intel_*` for passive intel (search/exposure/repo/cloud)
  - `api_*` for API checks
  - `auth_*` for identity checks
  - `webadv_*` for advanced web classes
  - `mail_*` for email posture
  - `delta_*` for change detection

---

## Safety + Compliance Requirements

- Google/Bing/Yandex dorking must use compliant APIs/providers where required.
- Default all new enrichers to `enabled: false`.
- Enforce strict scope host matching before any active probe.
- Add retries only for transient failure classes.
- Every new parser must have fixture tests (success + malformed + empty).

---

## Acceptance Criteria Per New Check

- Parser contract tests added under `internal/parsers/testdata/**`.
- `go test ./...` and `go vet ./...` pass.
- `go run ./cmd/asm validate` passes (including predicate compile checks).
- Findings correlate into canonical IDs without duplicate explosion.
- Report output includes new finding classes in top findings and host reports.
