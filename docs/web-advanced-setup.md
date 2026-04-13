# Web Advanced Setup (Desync / Cache / WAF Diff)

Autotron's advanced web class enrichers use `web-advanced`.

## Supported checks

- `desync` -> emits `request-smuggling-candidate` on behavioral drift.
- `cache-poison` -> emits `cache-poisoning-candidate` on marker/cache anomalies.
- `waf-diff` -> emits `waf-bypass-diff` on baseline/probe response profile drift.

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

Then run:

```bash
go run ./cmd/asm validate
go run ./cmd/asm scan -d example.com
```

## Safety notes

- These are low-volume heuristic probes, not exploit payloads.
- Keep scope gating strict and concurrency low.
