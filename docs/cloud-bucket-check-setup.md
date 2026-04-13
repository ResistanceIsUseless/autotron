# Cloud Bucket Check Setup (AWS/GCP/Azure)

Autotron's cloud posture enrichers use `cloud-bucket-check` for passive bucket/container exposure checks.

## Supported providers

- AWS S3 (`--provider aws`)
- Google Cloud Storage (`--provider gcp`)
- Azure Blob (`--provider azure`)

## What it checks

- Candidate bucket/container existence (derived from domain patterns).
- Public listing/read indicators from unauthenticated responses.
- Sample object names when listing is exposed.
- Region hints when available (AWS redirect responses).

## Build helper

```bash
go build -o cloud-bucket-check ./cmd/cloud-bucket-check
```

## Smoke tests

```bash
./cloud-bucket-check --provider aws --domain example.com --json
./cloud-bucket-check --provider gcp --domain example.com --json
./cloud-bucket-check --provider azure --domain example.com --json
```

Output fields:
- `provider`, `bucket`, `region`
- `public`, `listable`, `readable`
- `objects[]` (truncated sample)

## Enable in Autotron

In `configs/enrichers.yaml`, enable one or more:

- `s3_bucket_enum`
- `gcs_bucket_enum`
- `azure_blob_enum`

Then:

```bash
go run ./cmd/asm validate
go run ./cmd/asm scan -d example.com
```

## Safety notes

- This helper performs read-only unauthenticated GET requests.
- Candidate count is bounded (`--max-candidates`).
