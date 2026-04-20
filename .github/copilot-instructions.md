# Secamo Process Orchestrator - Copilot Agent Instructions

## Role And Scope

You are an expert Python backend engineer in this repository.

Primary stack:

- Python 3.11 target runtime (local dev may use newer Python, but generated code must stay 3.11-compatible)
- Temporal Python SDK (`temporalio`)
- AWS API Gateway + Lambda ingress proxy
- AWS (SSM, DynamoDB, S3) via `boto3`
- Pydantic v2 contracts

Before writing or modifying code, resolve external API/SDK behavior from documentation tools:

- Temporal workflows/activities/workers: `temporal-mcp`
- Microsoft Graph, Defender, Entra ID, M365: `microsoftdocs/mcp`
- Third-party Python libraries: `io.github.upstash/context7`

Do not guess API signatures.

## Fast Start Commands

Use these commands by default unless task context requires otherwise:

```bash
pip install -r requirements.txt
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe -m workers.run_worker
docker compose -f terraform/temporal-compose/docker-compose.yml up -d
```

Reference:

- [README.md](../README.md)
- [workers/README.md](../workers/README.md)
- [terraform/modules/ingress/src/ingress/handler.py](../terraform/modules/ingress/src/ingress/handler.py)

## Source Of Truth And Drift Policy

When docs conflict, trust running code in this order:

1. Routing behavior: [shared/routing/defaults.py](../shared/routing/defaults.py) + [shared/routing/registry.py](../shared/routing/registry.py)
2. Workflow input shaping: [shared/temporal/dispatcher.py](../shared/temporal/dispatcher.py)
3. Worker registration and queue binding: [workers/run_worker.py](../workers/run_worker.py)
4. Contracts: [shared/models](../shared/models/) and [shared/providers](../shared/providers/)

Do not infer active workflow catalog from stale README tables alone.

## Architecture Boundaries (Non-Negotiable)

Respect the 5-layer model:

```text
Incoming Webhook/Event
  -> [L1] API Gateway + Lambda Authorizer
  -> [L2] Ingress Service / Lambda Proxy
  -> [L3] Temporal Workflows
  -> [L4] Activities + Connector Adapter Layer
  -> [L5] AWS services + provider APIs
```

Rules:

- Never call AWS services directly from workflow code.
- Never call provider APIs directly from workflow code.
- Never hardcode tenant credentials.
- Always retrieve tenant secrets from SSM path: `/secamo/tenants/{tenant_id}/{secret_type}/{key}`.

Reference:

- [ARCHITECTURE.md](../ARCHITECTURE.md)
- [activities/tenant.py](../activities/tenant.py)

## Queue, Routing, And Worker Consistency Rules

Queue names are defined in [shared/config.py](../shared/config.py):

- `user-lifecycle`
- `edr`
- `ticketing`
- `interactions`
- `audit`
- `polling`

Any route changes must be mirrored in worker registration.

Hard rule:

- If you add or rename a route target workflow, update [workers/run_worker.py](../workers/run_worker.py) in the same change set.
- Validate startup parity via `_validate_route_worker_parity(...)` in [workers/run_worker.py](../workers/run_worker.py).

## Placement Conventions

Place new code in the narrowest correct layer:

- Temporal activities: `activities/`
- Temporal workflows: `workflows/` and `workflows/child/`
- Provider connectors: `connectors/` (must extend [connectors/base.py](../connectors/base.py))
- Connector registration: [connectors/registry.py](../connectors/registry.py)
- Domain contracts/models: `shared/models/`
- Provider contracts (protocols, provider enums/types, secret mapping): `shared/providers/`
- Shared routing/ingress/auth contracts: `shared/routing/`, `shared/ingress/`, `shared/auth/`
- Worker queue registration: [workers/run_worker.py](../workers/run_worker.py)
- Infrastructure changes: `terraform/modules/` or `terraform/environments/`

For new connectors, always do all three:

1. Implement connector class extending `BaseConnector`.
2. Register it in the connector registry.
3. Add tests under `tests/`.

## Contract Ownership And Typed Boundaries

Single-source ownership is mandatory:

- `shared.models` owns domain/event contracts (workflow inputs, canonical envelopes/events).
- `shared.providers` owns provider capability contracts and provider typing.

Rules:

- Do not create alternate provider protocols/enums outside `shared/providers/*`.
- Do not create a top-level `contracts/` package.
- Prefer typed Pydantic contracts over ad-hoc dict boundaries.

## SOC Signal Design Pattern (Current Implementation)

For `defender.security_signal` flows, the codebase uses a three-part pattern that must stay consistent:

1. Route selection in [shared/routing/defaults.py](../shared/routing/defaults.py):
   - Use `register_rule(...)` predicates that check both:
     - `payload.event_type == "defender.security_signal"`
     - `payload.provider_event_type == <signal-slug>`
2. Input normalization in [shared/temporal/dispatcher.py](../shared/temporal/dispatcher.py):
   - `_workflow_input_for_route(...)` maps workflow names to normalizers.
   - Dedicated SOC signal workflows receive `SecurityCaseInput`, not `Envelope`.
3. Worker registration in [workers/run_worker.py](../workers/run_worker.py):
   - Dedicated signal workflows are registered on queue `edr`.

Critical guardrails:

- Do not register signal slugs (`signin_log`, `risky_user`, etc.) as event-type keys via `registry.register(...)`; those keys are unreachable for envelope resolution.
- Keep the fallback `defender.security_signal -> SocAlertTriageWorkflow` route as catch-all for unknown future signal types.

## Normalization Pattern Rules

Normalization is transport-layer behavior, not workflow business logic.

Rules:

- Keep normalizers in `shared/normalization/*`.
- Keep workflow input conversion in [shared/temporal/dispatcher.py](../shared/temporal/dispatcher.py).
- Do not call `normalize_*` functions from dedicated signal workflows.
- Dedicated signal workflows must consume `SecurityCaseInput` directly.

Current typed input split:

- `IamOnboardingWorkflow` consumes `UserLifecycleCaseInput`.
- `SigninAnomalyDetectionWorkflow`, `RiskyUserTriageWorkflow`, `DeviceComplianceRemediationWorkflow`, and `AuditLogAnomalyWorkflow` consume `SecurityCaseInput`.
- `SocAlertTriageWorkflow` remains envelope-based fallback behavior.

## Workflow Engineering Rules

Workflow code must remain deterministic:

- No direct network, filesystem, or AWS I/O inside workflows.
- No `datetime.now()`, `random`, or other non-deterministic behavior.
- Prefer `workflow.now()` when a logical timestamp is needed.

Activity execution rules:

- Use explicit `start_to_close_timeout` and `retry_policy` on every `workflow.execute_activity(...)` call.
- Apply bootstrap pattern first, then runtime retries:
  - `bootstrap_tenant(...)` with static retry/timeout constants
  - `runtime_retry = RetryPolicy(maximum_attempts=config.max_activity_attempts)`

Observability and searchability rules:

- Upsert search attributes (`TenantId`, `CaseType`, `Severity`) for SOC case workflows.
- Ensure `emit_workflow_observability(...)` is called on every terminal path, including early exits.

Prefer helper-first orchestration from [shared/workflow_helpers.py](../shared/workflow_helpers.py):

- `bootstrap_tenant(...)`
- `resolve_threat_intel(...)`
- `create_soc_ticket(...)`
- `emit_workflow_observability(...)`

## Anti-Parallel Implementation Rules (Mandatory)

To prevent architecture drift:

1. One capability, one interface:

- Define provider capability contracts only in [shared/providers/protocols.py](../shared/providers/protocols.py).
- Define provider identifiers/type aliases and provider-to-secret mapping only in [shared/providers/types.py](../shared/providers/types.py).

2. One activity surface per capability:

- Activities call provider capabilities through factory + adapter; do not add parallel direct connector/API paths.

3. No shadow routing/dispatch logic:

- Routing decisions belong in [shared/routing/defaults.py](../shared/routing/defaults.py) + [shared/routing/registry.py](../shared/routing/registry.py).
- Input normalization for routed workflows belongs in [shared/temporal/dispatcher.py](../shared/temporal/dispatcher.py).

4. No parallel legacy + new flow for the same use case:

- If introducing replacement behavior, remove obsolete call paths in the same change set unless migration explicitly requires temporary coexistence.

## Decision Matrix For New Work In Shared

Before adding code, classify the change and place it in exactly one layer:

1. New boundary contract:

- Domain/event payload contracts: add/update model in `shared/models/*`.
- Provider capability/type contracts: add/update model in `shared/providers/*`.

2. Provider/channel/route selection rule:

- Add/update registry or factory logic; do not hardcode in workflows/activities.

3. Provider-specific API translation:

- Implement in connector/provider adapter, not in workflow code.

4. Temporal start/signal transport:

- Implement in `shared/temporal/*` abstractions.

5. Auth verification behavior:

- Implement validator in `shared/auth/validators/*` and register centrally.

If a change spans multiple layers, split commits by layer when practical.

## Testing Requirements

Every activity, workflow, routing, dispatcher, and worker registration change needs unit coverage.

Rules:

- Use `pytest` (configured via [pytest.ini](../pytest.ini)).
- Mock AWS, Graph, connector, and Temporal boundaries; no live services in unit tests.
- Prefer focused tests near behavior:
  - `tests/normalization/*`
  - `tests/routing/*`
  - `tests/test_dispatcher_*`
  - `tests/test_worker_*`
  - `tests/test_activities/*`

For route + workflow wiring changes, add/refresh all of:

1. Predicate/route resolution tests
2. Dispatcher input-shape tests
3. Worker registration/parity tests
4. Structural workflow guardrail tests (AST-level when appropriate)

## Project-Specific Pitfalls

- Avoid eager imports that trigger side effects at import time.
- Preserve frozen Pydantic contracts and deterministic workflow inputs.
- Keep connector error translation explicit; do not return success-looking payloads on failures.
- Keep route tables, dispatcher mapping, and worker workflow registration synchronized in one change set.

## Quality Bar

- Use type annotations on all new/modified functions.
- Prefer existing contracts over new ad-hoc schemas.
- Keep workflows thin and deterministic; put side effects in activities.
- Add concise docstrings for public APIs and non-obvious behavior.
- Read nearest existing implementation before introducing abstractions.

## Link, Do Not Duplicate

When updating docs/comments, link to canonical files instead of copying large stale sections:

- [README.md](../README.md)
- [ARCHITECTURE.md](../ARCHITECTURE.md)
- [workers/README.md](../workers/README.md)
- [workflows/README.md](../workflows/README.md)
- [shared/README.md](../shared/README.md)
- [connectors/README.md](../connectors/README.md)
- [tests/README.md](../tests/README.md)
