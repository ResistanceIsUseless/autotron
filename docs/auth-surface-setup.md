# Auth Surface Setup (OIDC Discovery)

Autotron's `oidc_discovery` enricher uses the `auth-surface` helper.

## What it checks

- OIDC discovery document exposure (`/.well-known/openid-configuration`, OAuth authorization server metadata).
- Issuer host and scheme sanity.
- `jwks_uri` presence and reachability.
- JWKS JSON validity and empty-key conditions.
- PKCE support sanity (`S256` presence when advertised methods exist).

## Build

```bash
go build -o auth-surface ./cmd/auth-surface
```

## Smoke test

```bash
./auth-surface --url https://login.example.com --mode oidc --json
```

Expected output: JSONL records with fields:
- `url`, `type`, `severity`, `confidence`, `details`

## Enable in Autotron

In `configs/enrichers.yaml` set:

- `name: oidc_discovery`
- `enabled: true`

Then run:

```bash
go run ./cmd/asm validate
go run ./cmd/asm scan -d example.com
```

## Safety

- Read-only HTTP GET checks only.
- Scope still enforced by engine gates before enrichment.
