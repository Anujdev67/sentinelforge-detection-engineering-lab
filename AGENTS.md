# SentinelForge contributor guide

## Repository map

- `apps/api/` — FastAPI, SQLAlchemy, services, migrations, and API tests.
- `apps/dashboard/` — React, TypeScript, Vite, UI components, and frontend tests.
- `detections/` — one versioned pack per rule: metadata, KQL, Sigma where valid, fixtures, and expected output.
- `evaluators/` — Python detection registry and local behavioral counterparts to KQL.
- `telemetry/` — schemas, generators, normalized models, and synthetic scenarios.
- `soar/` — safe local playbooks and Logic Apps artifacts.
- `infrastructure/terraform/` — Azure security-resource representations; validation only.
- `scripts/` — setup, demo, validation, safety, and report commands.
- `tests/` — cross-cutting unit, integration, detection, and safety tests.
- `docs/` — architecture, case studies, incident reports, screenshots, and recruiter guide.

## Standard commands

- `make setup` — create local configuration and install development dependencies.
- `make demo` — safely reset demo data, generate telemetry, evaluate rules, correlate incidents, and print results.
- `make test` — backend, detection, integration, and frontend tests.
- `make lint` — Ruff, MyPy, ESLint, and TypeScript checks.
- `make validate` — schemas, KQL, Sigma, Terraform, Compose, links, secrets, and prohibited-data checks.
- `docker compose up --build` — start PostgreSQL, API, and dashboard.
- Windows without Make: use the matching `./scripts/dev.ps1 <command>` action.

## Security restrictions

- Use synthetic telemetry only. Never add real logs, incidents, identities, tenant/subscription IDs, credentials, customer names, employer names, screenshots, or SOPs.
- Use fictional `*.example` domains and documentation-safe IP ranges. Keep prohibited names out of fixtures and UI copy.
- Do not add offensive exploitation, credential guessing, credential theft, persistence, evasion, or real containment code.
- Containment is local simulation only: require recorded human approval and write an audit entry. Never call real Entra ID, Defender, endpoint, firewall, AWS, email, Teams, or ServiceNow mutation APIs.
- Never commit `.env`, tokens, keys, state files, databases, evidence exports, or generated secrets.
- Never run or automate `terraform apply`. Do not create Azure resources.
- Never claim the Python evaluator executes KQL; KQL is authoritative cloud content and Python is a limited behavioral counterpart.
- Demo reset code must verify the demo-mode flag and an allowlisted database target before deleting local records.

## Coding standards

- Python 3.12; type every public function; Pydantic v2 at boundaries; SQLAlchemy 2 typed mappings; UTC-aware timestamps; Ruff formatting/lint; strict MyPy for application code.
- Keep services deterministic and dependency-injected. Separate API routes, persistence, correlation, and evaluator logic. Do not hide detection thresholds in code when they belong in rule metadata.
- TypeScript uses strict mode, functional React components, semantic HTML, accessible names, visible focus, and no `any` without a documented boundary.
- Detection IDs are immutable and globally unique. Every rule change updates its version and changelog and retains positive/negative regression fixtures.
- KQL must be readable, parameterized with `let`, include a time bound, expose mapped entities, and note table assumptions.
- Sigma must parse against the project profile and must not assert unsupported field mappings.
- JSON and YAML files use stable ordering where practical; dates and timestamps use ISO 8601 UTC.
- Tests must assert behavior and safety properties, not implementation trivia. No skipped test without a written environmental reason.
- Documentation describes only implemented behavior and links to real repository paths.

## Working sequence

1. Read `PLANS.md` and this file.
2. Work on only the active milestone and preserve unrelated changes.
3. Add or update tests with implementation.
4. Run the milestone's focused tests, lint, and validation.
5. Fix failures before advancing; document unavailable external tooling honestly.
6. Keep changes reviewable and avoid generated build/cached files.

## Definition of done

A change is done when it is implemented end-to-end, has positive and negative coverage where applicable, passes formatting/type/test/schema/security checks, works in the supported local path, contains no placeholder or dead controls, updates relevant documentation, respects the simulation boundary, and makes no unsupported claim. The repository is done only when the evidence ledger in `PLANS.md` is complete and the user-facing final report is grounded in actual validation output.
