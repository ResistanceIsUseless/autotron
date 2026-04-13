# Web Advanced Setup (Desync / Cache / WAF Diff)

Autotron's advanced web class enrichers use `web-advanced`.

## Supported checks

- `desync` -> emits `request-smuggling-candidate` on behavioral drift.
- `cache-poison` -> emits `cache-poisoning-candidate` on marker/cache anomalies.
- `waf-diff` -> emits `waf-bypass-diff` on baseline/probe response profile drift.

Additional enrichers currently mapped to these checks:

- `ssrf_gadget_discovery` (heuristic, mapped through `waf-diff`)
- `idor_candidate_mapper` (heuristic, mapped through `cache-poison`)
- `csrf_policy_audit` (heuristic, mapped through `desync`)

## Build helper

```bash
go build -o web-advanced ./cmd/web-advanced
```

## Smoke tests

```bash
./web-advanced --url https://example.com --check desync --json
./web-advanced --url https://example.com --check cache-poison --json
./web-advanced --url https://example.com --check waf-diff --json
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
