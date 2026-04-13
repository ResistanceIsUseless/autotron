# Mail Posture Setup

Autotron's `mx_posture_audit`, `spf_dkim_dmarc_audit`, and `smtp_open_relay_probe` enrichers use `mail-posture`.

## What it checks

- MX posture (`--check mx`).
- SPF/DKIM/DMARC posture (`--check spf-dkim-dmarc`).
- SMTP relay heuristic probe against MX hosts (`--check smtp-relay`).

## Build helper

```bash
go build -o mail-posture ./cmd/mail-posture
```

## Smoke test

```bash
./mail-posture --domain example.com --check mx --json
./mail-posture --domain example.com --check spf-dkim-dmarc --json
./mail-posture --domain example.com --check smtp-relay --timeout 15s --json
```

Output fields:
- `type`, `severity`, `details`, `domain`

## Enable in Autotron

In `configs/enrichers.yaml` set:

- `name: mx_posture_audit`
- `name: spf_dkim_dmarc_audit`
- `name: smtp_open_relay_probe`
- `enabled: true`

Then run:

```bash
go run ./cmd/asm validate
go run ./cmd/asm scan -d example.com
```
