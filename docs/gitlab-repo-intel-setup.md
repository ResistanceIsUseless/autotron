# GitLab Repo Intel Setup

Autotron's `gitlab_code_search_passive` enricher uses `repo-intel --provider gitlab` via GitLab's official API.

## Compliance model

- Uses GitLab REST API (`/projects`, repository tree/files)
- Auth via private token
- Passive repository leak discovery only

## Prerequisites

```bash
export GITLAB_TOKEN="<your_gitlab_token>"
```

Optional for self-hosted:

```bash
export GITLAB_API="https://gitlab.example.com/api/v4"
```

## Build helper

```bash
go build -o repo-intel ./cmd/repo-intel
```

## Smoke test

```bash
./repo-intel --provider gitlab --domain example.com --json --max-results 20
```

## Enable in Autotron

In `configs/enrichers.yaml`, set:

- `name: gitlab_code_search_passive`
- `enabled: true`

Then run:

```bash
go run ./cmd/asm validate
go run ./cmd/asm scan -d example.com
```
