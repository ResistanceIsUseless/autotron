# Mobile Artifact Recon Setup (APK/IPA Endpoint Extraction)

Autotron's `apk_endpoint_extract` and `ipa_endpoint_extract` enrichers use the `mobile-artifact` helper.

## What it does

- Downloads a bounded slice of an APK/IPA artifact.
- Extracts printable strings and identifies absolute and API-like relative endpoint candidates.
- Emits JSONL records compatible with `mobile_artifact_json` parser.

## Build

```bash
go build -o mobile-artifact ./cmd/mobile-artifact
```

Ensure `mobile-artifact` is in `PATH` (or set an absolute `bin` path in `configs/enrichers.yaml`).

## Smoke tests

```bash
./mobile-artifact --artifact-url https://downloads.example.com/app.apk --artifact-type apk --json --max-endpoints 50
./mobile-artifact --artifact-url https://downloads.example.com/app.ipa --artifact-type ipa --json --max-endpoints 50
```

Expected output fields:

- `artifact_url`, `artifact_type`
- `endpoint_url`, `method`, `path`
- `finding`, `severity`, `confidence`, `details`, `evidence`

## Enable in Autotron

In `configs/enrichers.yaml`, set one or both to `enabled: true`:

- `apk_endpoint_extract`
- `ipa_endpoint_extract`

Then run:

```bash
go run ./cmd/asm validate
go run ./cmd/asm scan -d example.com
```

## Safety notes

- Passive artifact analysis only.
- Download size is bounded (`--max-bytes`).
- Scope gating still enforced by the engine.
