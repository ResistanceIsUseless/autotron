# URL Shortener Intel Setup

Autotron's `url_shortener_search_passive` enricher uses `url-shortener-intel` to find shortened links that resolve into potential target assets.

## Why this avoids huge storage

- Uses search APIs (Google/Bing/Yandex) instead of downloading historical corpora.
- Resolves only discovered short links with bounded redirect depth.
- Stores only compact JSONL evidence per hit.

## Build helper

```bash
go build -o url-shortener-intel ./cmd/url-shortener-intel
```

## Credentials

Use one supported engine and set credentials:

```bash
export GOOGLE_CSE_API_KEY="<key>"
export GOOGLE_CSE_CX="<cx>"

# or
export BING_SEARCH_API_KEY="<key>"

# or
export YANDEX_XML_USER="<user>"
export YANDEX_XML_KEY="<key>"
```

## Smoke test

```bash
./url-shortener-intel --engine google --domain example.com --json --max-results 20 --max-redirects 6
```

## Enable in Autotron

In `configs/enrichers.yaml`, set:

- `name: url_shortener_search_passive`
- `enabled: true`

Then run:

```bash
go run ./cmd/asm validate
go run ./cmd/asm scan -d example.com
```
