# API Surface Setup (OpenAPI + GraphQL)

Autotron's `openapi_discovery` and `graphql_surface` enrichers use the `api-surface` helper.

## What it does

- **OpenAPI mode**
  - checks common spec paths (`/openapi.json`, `/swagger.json`, `/v3/api-docs`, ...)
  - emits endpoint records from `paths`.
  - emits finding `openapi-exposed` when schema is exposed.

- **GraphQL mode**
  - probes `/graphql` and `/api/graphql`.
  - attempts safe introspection request.
  - emits finding `graphql-introspection-enabled` on confirmed introspection.

## Build

```bash
go build -o api-surface ./cmd/api-surface
```

Ensure `api-surface` is in `PATH` (or set absolute path in YAML).

## Smoke tests

```bash
# OpenAPI discovery
./api-surface --url https://example.com --mode openapi --json --max-endpoints 50

# GraphQL probe
./api-surface --url https://example.com --mode graphql --json
```

## Enable enrichers

In `configs/enrichers.yaml` set:

- `openapi_discovery.enabled: true`
- `graphql_surface.enabled: true`

Then run:

```bash
go run ./cmd/asm validate
go run ./cmd/asm scan -d example.com
```

## Safety notes

- Requests are low-impact and bounded.
- Keep concurrency modest and rely on existing scope guards.
