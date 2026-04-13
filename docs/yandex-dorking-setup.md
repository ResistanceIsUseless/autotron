# Yandex Dorking Setup (Compliant XML API)

Autotron's `yandex_dork_passive` enricher uses `dorkintel --engine yandex` with Yandex XML Search.

## Compliance model

- Uses official endpoint: `https://yandex.com/search/xml`
- Requires XML API credentials (`user`, `key`)
- Passive search intelligence only

## Prerequisites

Set credentials:

```bash
export YANDEX_XML_USER="<your_yandex_xml_user>"
export YANDEX_XML_KEY="<your_yandex_xml_key>"
```

## Build helper

```bash
go build -o dorkintel ./cmd/dorkintel
```

## Smoke test

```bash
./dorkintel --engine yandex --domain example.com --json --max-results 20
```

## Enable in Autotron

In `configs/enrichers.yaml`, set:

- `name: yandex_dork_passive`
- `enabled: true`

Then run:

```bash
go run ./cmd/asm validate
go run ./cmd/asm scan -d example.com
```
