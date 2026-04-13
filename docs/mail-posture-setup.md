# Mail Posture Setup

Autotron's `mx_posture_audit` enricher uses the `mail-posture` helper to run passive DNS posture checks.

## What it checks

- MX presence.
- SPF TXT presence and risky patterns (`+all`, missing `-all`).
- DMARC presence and policy strength (`p=none` vs quarantine/reject).

## Build helper

```bash
go build -o mail-posture ./cmd/mail-posture
```

## Smoke test

```bash
./mail-posture --domain example.com --json
```

Output fields:
- `type`, `severity`, `details`, `domain`

## Enable in Autotron

In `configs/enrichers.yaml` set:

- `name: mx_posture_audit`
- `enabled: true`

Then run:

```bash
go run ./cmd/asm validate
go run ./cmd/asm scan -d example.com
```
