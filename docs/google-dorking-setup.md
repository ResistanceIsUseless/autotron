# Google Dorking Setup (Compliant API)

Autotron's dorking enrichers are designed to use official provider APIs through the `dorkintel` helper binary.

## Why this is compliant

- Uses `customsearch.googleapis.com` official endpoint.
- Supports Bing via `api.bing.microsoft.com` official endpoint.
- Uses API key + Search Engine CX issued by Google.
- Does not scrape `google.com/search` HTML.
- Supports explicit rate delay and max result caps.

## Prerequisites

1. Create a Programmable Search Engine (CSE) and get its `cx` value.
2. Create a Google API key with access to Custom Search JSON API.
3. Export credentials in shell environment:

```bash
export GOOGLE_CSE_API_KEY="<your_api_key>"
export GOOGLE_CSE_CX="<your_cse_cx>"
export BING_SEARCH_API_KEY="<your_bing_key>"
```

## Build helper binary

```bash
go build -o dorkintel ./cmd/dorkintel
```

Ensure `dorkintel` is in `PATH`, or use an absolute `bin` path in `configs/enrichers.yaml`.

## Manual smoke test

```bash
./dorkintel --engine google --domain example.com --json --max-results 5

# Bing
./dorkintel --engine bing --domain example.com --json --max-results 5
```

Expected output: JSONL records with fields:
- `engine`
- `query`
- `url`
- `title`
- `snippet`
- `class`
- `rank`

## Enable in Autotron

Set in `configs/enrichers.yaml`:

- `name: google_dork_passive`
- `name: bing_dork_passive`
- `enabled: true`

Then validate and run:

```bash
go run ./cmd/asm validate
go run ./cmd/asm scan -d example.com
```

## Safety defaults

- Keep `concurrency` low (1-2) for dorking enrichers.
- Keep per-domain max results conservative (for quota + noise control).
- Keep this enricher passive-only.
