# Web Advanced Setup (Desync / Cache / WAF / SSRF / IDOR / CSRF)

Autotron's advanced web class enrichers use `web-advanced`.

## Supported checks

- `desync` -> emits `request-smuggling-candidate` on behavioral drift.
- `cache-poison` -> emits `cache-poisoning-candidate` on marker/cache anomalies.
- `waf-diff` -> emits `waf-bypass-diff` on baseline/probe response profile drift.
- `ssrf-gadget` -> emits `ssrf-gadget-candidate` on metadata/header tampering drift.
- `idor-map` -> emits `idor-candidate` on identifier variation response drift.
- `csrf-audit` -> emits `csrf-policy-gap` when token indicators are absent.

Additional enrichers currently mapped to these checks:

- `ssrf_gadget_discovery` (mapped through `ssrf-gadget`)
- `idor_candidate_mapper` (mapped through `idor-map`)
- `csrf_policy_audit` (mapped through `csrf-audit`)

## Build helper

```bash
go build -o web-advanced ./cmd/web-advanced
```

## Smoke tests

```bash
./web-advanced --url https://example.com --check desync --json
./web-advanced --url https://example.com --check cache-poison --json
./web-advanced --url https://example.com --check waf-diff --json
./web-advanced --url https://example.com --check ssrf-gadget --json
./web-advanced --url https://example.com/api/v1/users/123 --check idor-map --json --idor-path /api/v1/users/123
./web-advanced --url https://example.com/account/settings --check csrf-audit --json
```

## Enable in Autotron

In `configs/enrichers.yaml`, enable any of:

- `http_desync_probe`
- `cache_poison_probe`
- `waf_diff_probe`
- `ssrf_gadget_discovery`
- `idor_candidate_mapper`
- `csrf_policy_audit`

Then run:

```bash
go run ./cmd/asm validate
go run ./cmd/asm scan -d example.com
```

## Safety notes

- These are low-volume heuristic probes, not exploit payloads.
- Keep scope gating strict and concurrency low.
