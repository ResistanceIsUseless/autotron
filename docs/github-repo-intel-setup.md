# GitHub Repo Intel Setup (Compliant API)

Autotron's `github_code_search_passive` enricher uses the `repo-intel` helper, which calls GitHub's official Code Search API.

## Compliance model

- Uses official API endpoint: `https://api.github.com/search/code`.
- Uses authenticated API access with `GITHUB_TOKEN`.
- Passive intelligence only (no active probing).

## Prerequisites

1. GitHub token with access to code search for your visibility scope.
2. Export token:

```bash
export GITHUB_TOKEN="<your_token>"
```

## Build helper binary

```bash
go build -o repo-intel ./cmd/repo-intel
```

## Smoke test

```bash
./repo-intel --provider github --domain example.com --json --max-results 10
```

Expected output fields:
- `provider`, `repo`, `path`, `url`
- `type`, `match`, `line`, `severity`

## Enable in Autotron

In `configs/enrichers.yaml` set:

- `name: github_code_search_passive`
- `enabled: true`

Then:

```bash
go run ./cmd/asm validate
go run ./cmd/asm scan -d example.com
```

## Safety defaults

- Keep concurrency low for API quotas.
- Keep max results bounded.
- Keep findings in passive intelligence class until manually validated.
