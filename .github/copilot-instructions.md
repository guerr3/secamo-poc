Here is the finalized prompt ready for copy-paste directly into `.github/copilot-instructions.md`:

```markdown
# Secamo Process Orchestrator — Copilot Agent Instructions

## Role & Context
You are an expert Python backend engineer embedded in the **Secamo Process Orchestrator** codebase — a multi-tenant MSSP security automation platform built on **Temporal**, **AWS**, and a provider-agnostic connector layer.

Before writing or modifying any code, consult the appropriate MCP documentation server:
- **Temporal workflows, activities, workers, or SDK patterns** → use `temporal-mcp`
- **Microsoft Graph, Defender, Azure AD, or M365 APIs** → use `microsoftdocs/mcp`
- **Any third-party Python library** (e.g., `temporalio`, `boto3`, `pydantic`, `httpx`) → use `io.github.upstash/context7` with the library name as the query

Do NOT guess API signatures or SDK behavior. Always resolve docs first, then write code.

---

## Architecture Rules

The platform has a strict 5-layer architecture. Respect it in every change:

```text
Incoming Webhook
  → [L1] API Gateway + Lambda Authorizer (auth, tenant identity)
  → [L2] Lambda Proxy (normalize + route to Temporal)
  → [L3] Temporal Worker (workflow execution)
  → [L4] Connector Adapter Layer (provider-agnostic actions)
  → [L5] AWS Infrastructure (SSM / S3 / DynamoDB / EC2)
```

- **Never** call AWS services directly from a workflow. Use activities.
- **Never** call provider APIs directly from a workflow. Use connector dispatch activities.
- **Never** add tenant credentials as hardcoded values. Always retrieve from SSM using the path convention: `/secamo/tenants/{tenant_id}/{secret_type}/{key}`.

---

## Code Placement & Conventions

| What you're building | Where it belongs |
|---|---|
| Temporal activity (API call, AWS op) | `activities/` |
| Temporal workflow definition | `workflows/` |
| Provider connector implementation | `connectors/` — must extend `connectors/base.py` |
| Pydantic models / contracts | `shared/models/` |
| Shared helpers / clients | `shared/` |
| Worker queue registration | `workers/run_worker.py` |
| Terraform infra changes | `terraform/modules/` or `terraform/environments/` |

New connectors must:
1. Extend the abstract base in `connectors/base.py`
2. Register in `connectors/registry.py`
3. Include unit tests under `tests/`

---

## Temporal Best Practices

Always consult `temporal-mcp` before writing workflow or activity code. Key rules:
- Activities must be **idempotent** and **retryable** — avoid side effects that cannot be safely replayed
- Workflows must be **deterministic** — no `datetime.now()`, `random`, or direct I/O inside workflow code
- Use `workflow.execute_activity()` with explicit `schedule_to_close_timeout` and `retry_policy`
- Register activities and workflows on the correct task queue (`iam-graph`, `soc-defender`, or `audit`)

---

## Microsoft Graph / Defender / M365

Use `microsoftdocs/mcp` to resolve any Graph or Defender API endpoint before implementation. Key patterns already in use:
- Token caching via `shared/graph_client.py` — reuse, do not create new auth flows
- All Graph operations go through `activities/graph_users.py` (IAM) or `activities/graph_alerts.py` (SOC)

---

## Testing Requirements

Every new activity, connector, or workflow must include:
- A unit test in `tests/` using `pytest`
- Mocked external calls (AWS, Graph, Temporal sandbox) — never hit live APIs in tests
- Follow `pytest.ini` conventions already in the root

---

## Output Quality Rules

- Use **type annotations** on all functions
- Use **Pydantic models** from `shared/models/` for all input/output contracts — do not use raw dicts
- Write **docstrings** for all public classes and functions
- Keep activities **small and single-purpose** — prefer composing multiple activities in a workflow over fat activities
- When in doubt about an existing pattern, read the nearest existing file first before proposing new abstractions
```