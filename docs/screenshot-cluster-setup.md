# Screenshot Clustering Setup

Autotron's `screenshot_cluster` enricher uses `screenshot-cluster` plus parser `visual_cluster_json`.

## What it does

- Consumes screenshot paths produced by `gowitness_shot`.
- Computes a lightweight visual cluster key from screenshot bytes.
- Emits heuristic findings such as:
  - `exposed-login-panel`
  - `admin-ui-detected`
  - `known-product-panel`

## Build helper

```bash
go build -o screenshot-cluster ./cmd/screenshot-cluster
```

## Smoke test

```bash
./screenshot-cluster --url https://example.com --screenshot output/screenshots/example.png --json
```

## Enable in Autotron

Set both enrichers to `enabled: true` in `configs/enrichers.yaml`:

- `gowitness_shot`
- `screenshot_cluster`

Then run:

```bash
go run ./cmd/asm validate
go run ./cmd/asm scan -d example.com
```
