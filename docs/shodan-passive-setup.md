# Shodan Passive Exposure Setup

Autotron's `shodan_host_passive` enricher uses the `exposure-intel` helper, which calls the official Shodan API.

## Compliance model

- Uses official endpoint: `https://api.shodan.io/shodan/host/<ip>`.
- Uses API key auth.
- Passive-only enrichment (no active probing in this step).

## Prerequisites

1. Shodan account with API access.
2. Export API key:

```bash
export SHODAN_API_KEY="<your_shodan_api_key>"
```

## Build helper binary

```bash
go build -o exposure-intel ./cmd/exposure-intel
```

Ensure `exposure-intel` is in `PATH` (or set absolute path in `configs/enrichers.yaml`).

## Smoke test

```bash
./exposure-intel --provider shodan --ip 1.1.1.1 --json --max-services 5
```

Expected output: JSONL records with fields:
- `provider`, `ip`, `port`, `protocol`, `service`
- `product`, `version`, `banner`
- `cve[]`, `risk`

## Enable in Autotron

In `configs/enrichers.yaml` set:

- `name: shodan_host_passive`
- `enabled: true`

Then run:

```bash
go run ./cmd/asm validate
go run ./cmd/asm scan -d example.com
```

## Safety defaults

- Keep this enricher passive-only.
- Keep concurrency moderate (2-4) and avoid broad unscoped IP expansion.
