# Censys Passive Exposure Setup

Autotron's `censys_host_passive` enricher uses `exposure-intel --provider censys` with Censys Search API v2.

## Compliance model

- Uses official endpoint: `https://search.censys.io/api/v2/hosts/<ip>`
- Uses API ID + secret via HTTP Basic auth
- Passive-only host exposure enrichment

## Prerequisites

```bash
export CENSYS_API_ID="<your_censys_api_id>"
export CENSYS_API_SECRET="<your_censys_api_secret>"
```

## Build helper

```bash
go build -o exposure-intel ./cmd/exposure-intel
```

## Smoke test

```bash
./exposure-intel --provider censys --ip 1.1.1.1 --json --max-services 20
```

## Enable in Autotron

In `configs/enrichers.yaml`, set:

- `name: censys_host_passive`
- `enabled: true`

Then run:

```bash
go run ./cmd/asm validate
go run ./cmd/asm scan -d example.com
```
