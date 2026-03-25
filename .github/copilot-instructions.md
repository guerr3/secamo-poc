# Secamo Process Orchestrator - Copilot Agent Instructions

## Role And Scope

You are an expert Python backend engineer in this repository.

Primary stack:

- Python 3.11
- Temporal Python SDK (`temporalio`)
- FastAPI ingress service
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
python -m pytest -q
python -m workers.run_worker
docker compose -f terraform/temporal-compose/docker-compose.yml up -d
```

Reference:

- [README.md](../README.md)
- [workers/README.md](../workers/README.md)
- [terraform/modules/ingress/src/ingress/handler.py](../terraform/modules/ingress/src/ingress/handler.py)

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

## Source Of Truth For Queues And Routing

Queue names are defined in [shared/config.py](../shared/config.py).

Current queues:

- `iam-graph`
- `soc-defender`
- `audit`
- `poller`

Workflow/activity registration by queue is in [workers/run_worker.py](../workers/run_worker.py).

Ingress routing defaults are in:

- [shared/routing/defaults.py](../shared/routing/defaults.py)
- [shared/routing/registry.py](../shared/routing/registry.py)
- [terraform/modules/ingress/src/ingress/handler.py](../terraform/modules/ingress/src/ingress/handler.py)

Keep these mappings consistent when adding or renaming routes/workflows.

## Placement Conventions

Place new code in the narrowest correct layer:

- Temporal activities: `activities/`
- Temporal workflows: `workflows/` and `workflows/child/`
- Provider connectors: `connectors/` (must extend [connectors/base.py](../connectors/base.py))
- Connector registration: [connectors/registry.py](../connectors/registry.py)
- Shared contracts/models: `shared/` subpackages (especially `shared/models/`, `shared/routing/`, `shared/ingress/`, `shared/auth/`)
- Worker queue registration: [workers/run_worker.py](../workers/run_worker.py)
- Infrastructure changes: `terraform/modules/` or `terraform/environments/`

For new connectors, always do all three:

1. Implement connector class extending `BaseConnector`.
2. Register it in the connector registry.
3. Add tests under `tests/`.

## Temporal Engineering Rules

Workflow code must remain deterministic:

- No direct network, filesystem, or AWS I/O inside workflows.
- No `datetime.now()`, `random`, or other non-deterministic behavior.
- Prefer `workflow.now()` when a logical timestamp is needed.

Activity code must be retry-safe:

- Keep activities idempotent.
- Translate transient failures to retryable errors.
- Use explicit timeouts/retry policy on `workflow.execute_activity(...)` calls.

Reference examples:

- [workflows/graph_subscription_manager.py](../workflows/graph_subscription_manager.py)
- [workflows/iam_onboarding.py](../workflows/iam_onboarding.py)
- [activities/\_activity_errors.py](../activities/_activity_errors.py)

## Graph, Defender, And Auth Patterns

Follow existing integration patterns:

- Reuse token caching/client logic in [shared/graph_client.py](../shared/graph_client.py).
- Keep Graph/Defender side effects in activities (for example [activities/graph_users.py](../activities/graph_users.py), [activities/graph_alerts.py](../activities/graph_alerts.py)).
- Keep ingress tenant resolution and validation logic aligned with [terraform/modules/ingress/src/ingress/handler.py](../terraform/modules/ingress/src/ingress/handler.py).

## Testing Requirements

Every new activity, workflow, or connector change should include unit tests:

- Use `pytest` (configured via [pytest.ini](../pytest.ini)).
- Mock AWS, Graph, connector, and Temporal boundaries; do not call live services in tests.
- Prefer focused tests near the changed behavior (for example `tests/test_activities/`, `tests/routing/`, `tests/contracts/`).

Reference:

- [tests/README.md](../tests/README.md)

## Project-Specific Pitfalls

- Avoid eager imports that trigger side effects at import time. Keep activity exports lazy in [activities/**init**.py](../activities/__init__.py).
- Preserve frozen Pydantic input contracts for Temporal-facing models where used (for replay safety).
- Keep connector error translation behavior explicit; do not hide failures behind success-looking payloads.

## Quality Bar

- Use type annotations on all new and modified functions.
- Use existing Pydantic contracts instead of raw dict payload plumbing where contracts already exist.
- Add concise docstrings for public functions/classes.
- Prefer small single-purpose activities composed by workflows.
- Read nearest existing implementation before introducing new abstractions.

## Link, Do Not Duplicate

When updating documentation-like instructions or comments, link to canonical files instead of duplicating large blocks:

- [README.md](../README.md)
- [ARCHITECTURE.md](../ARCHITECTURE.md)
- [activities/README.md](../activities/README.md)
- [workflows/README.md](../workflows/README.md)
- [connectors/README.md](../connectors/README.md)
- [shared/README.md](../shared/README.md)
- [terraform/README.md](../terraform/README.md)
