# Delta Intelligence Setup (Continuous Drift Checks)

Autotron's `delta_new_exposure`, `delta_new_findings`, and `delta_surface_regression` enrichers use `delta-intel` with parser `delta_report_json`.

## What it does

- Compares a current scan run summary against the most recent prior summary.
- Emits drift findings for:
  - `delta-new-exposure` (service growth)
  - `delta-new-findings` (finding count growth)
  - `delta-surface-regression` (critical/high growth or coverage drop)

## Runtime data flow

- The engine now writes per-run summaries to `output/delta/<scan_run_id>.json` on completed runs.
- `delta-intel` reads these summary files from `--state-dir`.

## Build

```bash
go build -o delta-intel ./cmd/delta-intel
```

## Smoke tests

```bash
./delta-intel --run-id <current_scan_run_id> --state-dir ./output/delta --check all --json
./delta-intel --run-id <current_scan_run_id> --state-dir ./output/delta --check new-findings --json
```

Expected output fields:

- `type`, `title`, `severity`, `confidence`, `details`
- `metric`, `current_count`, `previous_count`
- `current_scan_run_id`, `previous_scan_run_id`

## Enable in Autotron

In `configs/enrichers.yaml`, set these to `enabled: true` as desired:

- `delta_new_exposure`
- `delta_new_findings`
- `delta_surface_regression`

Then run:

```bash
go run ./cmd/asm validate
go run ./cmd/asm scan -d example.com
```

## Notes

- Requires at least two summary files for comparison.
- Defaults are conservative and heuristic; treat as triage signals.
