# FOFA Passive Exposure Setup

Autotron's `fofa_host_passive` enricher uses `exposure-intel --provider fofa` with FOFA's official API.

## Compliance model

- Uses FOFA API endpoint: `/api/v1/search/all`
- Auth via account email + API key
- Passive host exposure intel only

## Prerequisites

```bash
export FOFA_EMAIL="<your_fofa_email>"
export FOFA_KEY="<your_fofa_api_key>"
```

## Build helper

```bash
go build -o exposure-intel ./cmd/exposure-intel
```

## Smoke test

```bash
./exposure-intel --provider fofa --ip 1.1.1.1 --json --max-services 20
```

## Enable in Autotron

In `configs/enrichers.yaml`, set:

- `name: fofa_host_passive`
- `enabled: true`

Then run:

```bash
go run ./cmd/asm validate
go run ./cmd/asm scan -d example.com
```
