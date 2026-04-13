# AI Integration - Next Phase Draft

This document defines the next implementation phase for AI in Autotron, focused on:

1. report writing assistance, and
2. false-positive (FP) validation support.

The goal is to add analyst acceleration without weakening deterministic scan fidelity.

---

## Objectives

- Add optional AI-generated host report narrative on top of existing deterministic report output.
- Add optional AI triage verdicts for findings (`likely_true_positive`, `likely_false_positive`, `needs_manual_review`).
- Persist AI assessments as additive metadata, never as destructive replacements.
- Keep AI integration modular and provider-agnostic.

## Non-goals (for this phase)

- No autonomous exploitation.
- No auto-closing findings without explicit operator action.
- No hard dependency on AI provider availability for `scan` or `validate`.

---

## Design Principles

- **Deterministic first**: current graph, parser, and report pipeline remains source of truth.
- **Optional AI**: AI features are explicitly invoked via CLI flags/commands.
- **Evidence-grounded**: model prompts must include normalized finding evidence and scope context.
- **Human-in-loop**: model output guides triage; operator decides final status changes.
- **Traceability**: store model name, prompt version, and timestamp with each assessment.

---

## Proposed Architecture

Add new package:

- `internal/ai/`
  - `provider.go` - interface + request/response model.
  - `openai_compat.go` - OpenAI-compatible implementation (URL/model/key configurable).
  - `prompts.go` - prompt builders + prompt version constants.
  - `schema.go` - strict JSON output schemas for report summary and finding triage.
  - `service.go` - orchestration, retries, timeout, validation, and mapping.

Existing integration points:

- `cmd/asm/main.go`
  - add `triage` command.
  - add `--ai-summary` option to `report` command.
- `internal/graph/graph.go`
  - persist AI assessment metadata to Finding nodes.
- `internal/graph/host_report_render.go`
  - append AI narrative section when requested.

---

## Data Model Additions (Finding node)

Additive properties only:

- `ai_verdict` (`likely_true_positive|likely_false_positive|needs_manual_review`)
- `ai_score` (0-100)
- `ai_reason` (short markdown/text)
- `ai_model` (e.g. `gpt-5.3-codex`)
- `ai_provider` (e.g. `openai_compat`)
- `ai_prompt_version` (e.g. `triage-v1`)
- `ai_assessed_at` (UTC timestamp)
- `ai_recommended_severity` (optional)
- `ai_recommended_confidence` (optional)

Optional host-level report field (persisted to file output only in this phase):

- `ai_summary` (executive summary + prioritized actions)

---

## CLI / UX Changes

### 1) Report AI summary

Extend report command:

- `asm report --host <fqdn> --ai-summary`
- `asm report --host <fqdn> --ai-summary --format markdown --save`

Behavior:

- Builds deterministic host report first.
- Sends normalized host report JSON to AI provider.
- Appends generated sections:
  - Executive Summary
  - Attack Path Hypotheses
  - Priority Fixes
  - Suggested Re-test Commands

If AI fails, deterministic report still returns.

### 2) Finding triage command

New command:

- `asm triage --finding <finding_id>`
- `asm triage --host <fqdn>`
- `asm triage --top 50 --severity medium,high`
- `asm triage --apply` (write AI fields back to graph)

Default behavior is preview-only unless `--apply` is set.

---

## Config / Environment

Phase 1 uses env vars (no required YAML changes):

- `AUTOTRON_AI_PROVIDER=openai_compat`
- `AUTOTRON_AI_MODEL=<model_name>`
- `AUTOTRON_AI_BASE_URL=<provider_url>`
- `AUTOTRON_AI_API_KEY=<secret>`
- `AUTOTRON_AI_TIMEOUT=20s` (optional)

Future phase can move these into `configs/asm.yaml` under `ai:`.

---

## Prompt Contracts

### A) Triage output schema (strict JSON)

```json
{
  "verdict": "likely_true_positive|likely_false_positive|needs_manual_review",
  "score": 0,
  "confidence_band": "low|medium|high",
  "why": ["..."],
  "evidence_gaps": ["..."],
  "next_checks": ["..."],
  "risk_if_true": "...",
  "recommended_severity": "info|low|medium|high|critical",
  "recommended_confidence": "tentative|firm|confirmed"
}
```

### B) Report summary schema (strict JSON)

```json
{
  "executive_summary": "...",
  "top_risks": ["..."],
  "attack_paths": ["..."],
  "priority_fixes": ["..."],
  "retest_commands": ["..."],
  "limitations": ["..."]
}
```

---

## Safety Guardrails

- Strip/redact obvious secrets in evidence before prompt assembly.
- Enforce token/input size limits and truncate with explicit indicator.
- Reject invalid model output; never write malformed AI data to graph.
- If model confidence is low or output is ambiguous, force verdict to `needs_manual_review`.
- No automatic suppression or deletion of findings.

---

## Implementation Work Packages

### WP1 - AI core package

- Add `internal/ai` interfaces, OpenAI-compatible adapter, retry/timeout wrapper.
- Add unit tests with mocked transport.

### WP2 - Report integration

- Extend `asm report` with `--ai-summary`.
- Add renderer support for optional AI section.
- Add tests for fallback behavior when AI fails.

### WP3 - Triage command

- Add `asm triage` command with finding/host/top selection.
- Add preview table output + `--apply` persistence path.
- Add graph write method for AI fields.

### WP4 - Validation and docs

- Add validation for required AI env vars when AI flags are used.
- Add `docs/ai-setup.md` usage guide.
- Add examples to `README.md` command section.

---

## Acceptance Criteria

- `asm report --ai-summary` works and gracefully falls back on provider errors.
- `asm triage` returns structured verdicts and optional persistence works.
- AI metadata is queryable on findings without breaking existing report paths.
- `go test ./...`, `go vet ./...`, and `go run ./cmd/asm validate` all pass.
- No default scan path depends on AI connectivity.

---

## Rollout Plan

1. Merge AI core + report summary (read-only mode, no graph writes).
2. Merge triage preview command.
3. Enable `--apply` graph persistence.
4. Add optional profile/docs updates after field testing.

---

## Suggested First PR Scope

Keep PR 1 small:

- `internal/ai/` core
- `asm report --ai-summary`
- strict output schema validation
- docs + tests

Then ship triage command in PR 2.
