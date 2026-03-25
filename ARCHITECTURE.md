# Secamo Architecture Guide

> A developer-focused explanation of how the Secamo Process Orchestrator is structured, how its layers interact, and how to extend it.

---

## Table of Contents

1. [What Is Secamo?](#1-what-is-secamo)
2. [Key Technologies](#2-key-technologies)
3. [Repository Layout](#3-repository-layout)
4. [Architecture Layers](#4-architecture-layers)
5. [Task Queues](#5-task-queues)
6. [Multi-Tenancy Model](#6-multi-tenancy-model)
7. [Data Models](#7-data-models)
8. [End-to-End Event Walkthrough](#8-end-to-end-event-walkthrough)
9. [Temporal Patterns](#9-temporal-patterns)
10. [Connector Pattern](#10-connector-pattern)
11. [Developer Extension Guide](#11-developer-extension-guide)
12. [Testing Approach](#12-testing-approach)
13. [Infrastructure Overview](#13-infrastructure-overview)

---

## 1. What Is Secamo?

**Secamo** (Security Automation and Orchestration) is a **proof-of-concept multi-tenant MSSP** (Managed Security Service Provider) platform. Its goal is to automate common security operations tasks — user lifecycle management, SOC alert triage, human-in-the-loop approvals, and incident response — across multiple customer tenants using a single shared platform.

**Core automation use cases:**

| Use Case                      | Description                                                                                                                                                  |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| IAM Lifecycle                 | Automatically create, update, disable, and delete Microsoft Entra ID (Azure AD) users when HR/IAM events arrive.                                             |
| Defender Alert Triage         | Enrich Defender security alerts with user/device context, compute a risk score, and optionally use AI for triage recommendations.                            |
| Impossible Travel Detection   | Detect risky sign-ins, do threat intel lookups, request human analyst approval, and apply the analyst's decision (isolate device, disable user, or dismiss). |
| Graph Subscription Management | Continuously reconcile Microsoft Graph change notification subscriptions across all tenants.                                                                 |
| Polling-based Integration     | Periodically poll EDR providers (e.g., Defender, CrowdStrike) for new events when webhooks are unavailable.                                                  |

---

## 2. Key Technologies

| Technology                              | Version | Role                                                                                                  |
| --------------------------------------- | ------- | ----------------------------------------------------------------------------------------------------- |
| **Python**                              | 3.11    | Primary runtime language                                                                              |
| **Temporal** (`temporalio`)             | ≥ 1.9.0 | Durable workflow orchestration engine — provides retries, state persistence, signals, and HITL timers |
| **Pydantic**                            | v2      | All data models and input/output contracts between layers                                             |
| **AWS API Gateway + Lambda**            | —       | HTTP ingress boundary for provider webhooks, Graph notifications, and HITL callbacks                  |
| **Microsoft Graph SDK** (`msgraph-sdk`) | ≥ 1.2   | Graph and Defender API calls                                                                          |
| **azure-identity**                      | ≥ 1.15  | OAuth2 token acquisition for Microsoft Graph (client credentials flow)                                |
| **boto3**                               | ≥ 1.34  | AWS SDK — SSM Parameter Store (secrets), DynamoDB (audit, subscriptions, HITL tokens), S3 (evidence)  |
| **httpx**                               | ≥ 0.27  | Async HTTP client for connector integrations (Jira, etc.)                                             |
| **pytest** + **pytest-asyncio**         | ≥ 8.0   | Unit testing framework with async support                                                             |
| **Terraform**                           | —       | Infrastructure-as-Code for AWS resources and Temporal deployment                                      |
| **Docker / Compose**                    | —       | Local development stack bundling Temporal Server, worker, and ingress                                 |

### Why Temporal?

Temporal is the central design choice. It provides:

- **Durability** — workflow state survives worker restarts, crashes, and deployments.
- **Determinism enforcement** — workflow code cannot perform I/O or call non-deterministic functions; all side effects go through activities.
- **Long-running timers** — a HITL (Human-in-the-Loop) approval workflow can wait hours or days for an analyst response using a Temporal signal, without holding a thread or polling a database.
- **Built-in retries** — activity retry policies are declared in code; failed API calls retry automatically with configurable backoff.
- **Child workflows** — large flows (impossible travel, defender alert) are composed from reusable child workflows rather than monolithic functions.

---

## 3. Repository Layout

```
secamo-poc/
├── terraform/modules/ingress/src/ingress/  # [L2] Lambda proxy ingress handlers
├── workflows/           # [L3] Temporal workflow definitions (parent + child)
│   └── child/           #       Reusable child workflow stages
├── activities/          # [L4] Temporal activities — all external side effects live here
├── connectors/          # [L4] Provider adapter layer — abstracts EDR/ticketing/intel APIs
├── workers/             # Worker bootstrap — registers workflows/activities on task queues
├── shared/              # Cross-cutting: config, Graph client, SSM helpers, Pydantic models, mappers
│   ├── models/          #   All Pydantic contracts used as workflow/activity I/O
│   └── providers/       #   Runtime AI and ChatOps provider implementations
├── terraform/           # [L5] AWS infrastructure (API GW, Lambda auth, EC2 worker, RDS, S3, DynamoDB)
│   ├── environments/    #   PoC and temporal-test environment compositions
│   └── modules/         #   Reusable Terraform modules per concern
└── tests/               # Unit tests (pytest)
```

---

## 4. Architecture Layers

```
External Event / Webhook
        │
        ▼
┌───────────────────────────────────────────────────────────────────┐
│ L1 — AWS API Gateway + Lambda Authorizer                          │
│      Validates tenant HMAC/token, injects tenant_id header        │
│      terraform/modules/ingress/                                   │
└───────────────────────────────┬───────────────────────────────────┘
                                │ authenticated HTTP request
                                ▼
┌───────────────────────────────────────────────────────────────────┐
│ L2 — Ingress Lambda Proxy (`terraform/modules/ingress/src/ingress`)│
│      handler.py — receives API Gateway proxy events                │
│      validates provider signatures / Graph tokens                  │
│      normalizes payloads and dispatches routed workflow starts     │
│      handles signed HITL callback routes                           │
└───────────────────────────────┬───────────────────────────────────┘
                                │ Temporal SDK call
                                ▼
┌───────────────────────────────────────────────────────────────────┐
│ L3 — Temporal Workflows (deterministic orchestration)             │
│      workflows/ — parent workflows route events to child flows    │
│      workflows/child/ — reusable stages (ticket, HITL, IR, etc.) │
│      No I/O allowed here — all side effects delegated to L4       │
└───────────────────────────────┬───────────────────────────────────┘
                                │ workflow.execute_activity(...)
                                ▼
┌───────────────────────────────────────────────────────────────────┐
│ L4 — Activity + Connector Layer                                   │
│      activities/ — Python functions that perform external calls   │
│      connectors/ — provider-agnostic BaseConnector implementations│
│      shared/providers/ — AI triage + ChatOps provider instances   │
└───────────────────────────────┬───────────────────────────────────┘
                                │ API/SDK calls
                                ▼
┌───────────────────────────────────────────────────────────────────┐
│ L5 — AWS Services + External APIs                                 │
│      SSM Parameter Store — tenant secrets and config              │
│      DynamoDB — audit records, HITL tokens, subscriptions         │
│      S3 — evidence bundles                                        │
│      Microsoft Graph / Defender — user/device/alert APIs          │
│      Jira / ServiceNow / etc — ticketing                          │
└───────────────────────────────────────────────────────────────────┘
```

### Layer responsibilities in detail

#### L1 — API Gateway + Lambda Authorizer (`terraform/modules/ingress/`)

The Lambda authorizer (`src/authorizer/handler.py`) validates each inbound HTTP request against a per-tenant HMAC secret stored in SSM. If validation succeeds, the authorizer forwards the request to the Lambda proxy (`src/ingress/handler.py`), which validates provider signatures, normalises payloads, and dispatches routed workflow starts directly.

Note: for Graph notifications, tenant identity is represented in the route path (`/api/v1/graph/notifications/{tenant_id}`), while each notification item still carries `clientState` that is checked for the expected `secamo:{tenant_id}:` prefix.

Credential cache TTL is controlled by the `CACHE_TTL_SECONDS` environment variable (default 300 s).

#### L2 — Ingress Lambda Proxy (`terraform/modules/ingress/src/ingress/handler.py`)

The ingress Lambda proxy is the HTTP intake boundary for the orchestrator.

Active routes include:

- **`POST /api/v1/ingress/event/{tenant_id}`** — generic provider webhook ingress.
- **`POST /api/v1/ingress/internal`** — internal IAM ingress path.
- **`POST /api/v1/graph/notifications/{tenant_id}`** — Graph notifications route; if `validationToken` query parameter exists, immediately returns `200 text/plain` with the token for Graph subscription validation.
- **`GET /api/v1/hitl/respond`** — signed email token callback for HITL decisions.
- **`POST /api/v1/hitl/jira`** — Jira webhook callback that signals waiting HITL workflows.

For Graph notifications without `validationToken`, the handler validates the bearer token signature, validates optional Graph `validationTokens`, filters unsupported notification resources, normalizes supported items, and dispatches workflow starts through the shared route fan-out dispatcher.

#### L3 — Temporal Workflows (`workflows/`)

Workflows are **pure orchestration** — no I/O, no `datetime.now()`, no random numbers. They compose activity calls and child workflow starts into durable, replay-safe sequences.

**Parent workflows** (one per security event type):

| Workflow                           | Queue          | Trigger                                            |
| ---------------------------------- | -------------- | -------------------------------------------------- |
| `IamOnboardingWorkflow`            | `iam-graph`    | IAM lifecycle events (HR system / polling)         |
| `DefenderAlertEnrichmentWorkflow`  | `soc-defender` | Graph Defender alert notifications                 |
| `ImpossibleTravelWorkflow`         | `soc-defender` | Graph risky sign-in / risky user notifications     |
| `GraphSubscriptionManagerWorkflow` | `soc-defender` | Scheduled/manual subscription reconciliation       |
| `PollingManagerWorkflow`           | `poller`       | Started by onboarding per polling-enabled provider |

**Child workflows** in `workflows/child/` are reusable stages invoked by one or more parent workflows:

| Child Workflow                  | Role                                                                           |
| ------------------------------- | ------------------------------------------------------------------------------ |
| `AlertEnrichmentWorkflow`       | Connector enrichment + risk scoring                                            |
| `ThreatIntelEnrichmentWorkflow` | Fan-out threat intel lookups across configured providers                       |
| `TicketCreationWorkflow`        | Provider-agnostic ticket creation                                              |
| `HiTLApprovalWorkflow`          | Send approval request → wait for signal → apply timeout policy                 |
| `IncidentResponseWorkflow`      | Execute analyst decision (dismiss / isolate / disable user) + collect evidence |
| `UserDeprovisioningWorkflow`    | Revoke sessions + delete user in Graph                                         |

#### L4 — Activities and Connectors (`activities/`, `connectors/`)

Activities are regular async Python functions decorated with `@activity.defn`. They are the **only** place where external API calls, database writes, and file I/O are allowed.

Key activity groups:

| Module                                | Responsibility                               |
| ------------------------------------- | -------------------------------------------- |
| `graph_users.py`                      | User lifecycle in Microsoft Graph            |
| `graph_alerts.py`                     | Defender alert reads and enrichment          |
| `graph_devices.py`                    | Device isolation, scan, compliance           |
| `graph_signin.py`                     | Sign-in history and identity risk            |
| `graph_subscriptions.py`              | Change notification subscription management  |
| `connector_dispatch.py`               | Provider-agnostic gateway to connector layer |
| `tenant.py`                           | Tenant config and secrets from SSM/DynamoDB  |
| `hitl.py`                             | Issue HITL tokens and approval links         |
| `ticketing.py`                        | Create/update/close tickets via connectors   |
| `risk.py`                             | Compute risk score from alert context        |
| `triage.py`                           | AI triage via provider abstraction           |
| `evidence.py`                         | Write evidence bundle to S3                  |
| `audit.py`                            | Write audit record to DynamoDB               |
| `notify_email.py` / `notify_teams.py` | Send notifications via Graph Mail / Teams    |

The **connector layer** (`connectors/`) decouples activities from specific provider SDKs. Activities call `get_connector(provider, tenant_id, secrets)` from `connectors/registry.py`, which returns a `BaseConnector` instance. This means switching from Jira to ServiceNow requires only a config change, not an activity change.

#### L5 — AWS Services

All AWS calls are made from activities (never from workflows). The main services used:

| Service                 | Purpose                                                        | Path convention                                      |
| ----------------------- | -------------------------------------------------------------- | ---------------------------------------------------- |
| **SSM Parameter Store** | Tenant secrets and config                                      | `/secamo/tenants/{tenant_id}/{secret_type}/{key}`    |
| **DynamoDB**            | Audit trail, HITL approval tokens, Graph subscription metadata | Separate tables per concern                          |
| **S3**                  | Evidence bundle storage                                        | Bucket configured via `EVIDENCE_BUCKET_NAME` env var |

---

## 5. Task Queues

Temporal task queues partition work across worker types. Each worker process registers a specific set of workflows and activities:

| Queue          | Workflows                                                      | Activities                                                                           | Purpose                       |
| -------------- | -------------------------------------------------------------- | ------------------------------------------------------------------------------------ | ----------------------------- |
| `iam-graph`    | `IamOnboardingWorkflow`, `UserDeprovisioningWorkflow`          | User lifecycle, audit, tenant                                                        | Identity/IAM operations       |
| `soc-defender` | All SOC + child workflows + `GraphSubscriptionManagerWorkflow` | Graph alerts/devices/signin, ticketing, HITL, evidence, threat intel, triage, notify | Security operations           |
| `audit`        | —                                                              | `create_audit_log`, `collect_evidence_bundle`                                        | Dedicated audit writes        |
| `poller`       | `PollingManagerWorkflow`                                       | Connector dispatch, audit                                                            | Polling-based event ingestion |

All workers are started together from `workers/run_worker.py`, which imports and registers the appropriate activity and workflow lists for each queue.

---

## 6. Multi-Tenancy Model

Every workflow and activity carries a `tenant_id` string. Tenant isolation is enforced at two levels:

**Secrets isolation** — All credentials (Microsoft Graph client ID/secret, Jira API keys, etc.) are stored in AWS SSM under the path `/secamo/tenants/{tenant_id}/{secret_type}/{key}`. Activities retrieve them via `shared/ssm_client.py`. No credential is ever hardcoded or shared across tenants.

**Config isolation** — Per-tenant configuration (enabled features, provider choices, analyst email, timeout hours, etc.) is stored at `/secamo/tenants/{tenant_id}/config/*` and loaded into a `TenantConfig` Pydantic model by `activities/tenant.py`. This lets one tenant use Jira+CrowdStrike while another uses ServiceNow+Defender.

The `bootstrap_tenant(...)` helper in `shared/workflow_helpers.py` is called at the start of most parent workflows to load both config and the primary secrets concurrently before any business logic runs.

---

## 7. Data Models

All models are Pydantic v2 classes in `shared/models/`. They serve as the stable I/O contracts between every layer.

### Model hierarchy

```
shared/models/
├── canonical.py     — CanonicalEvent, SecurityEvent, UserContext, AlertData, NetworkContext, DeviceContext
├── domain.py        — TenantConfig, TenantSecrets, HiTLRequest, ApprovalDecision, IncidentResponseRequest,
│                      TicketCreationRequest, TicketResult, RiskScore, GraphUser, ...
├── ingress.py       — GraphNotificationEnvelope, GraphNotificationItem, IamIngressRequest
├── commands.py      — WorkflowCommand, StartWorkflowCommand, SignalWorkflowCommand
├── provider_events.py — DefenderWebhook, JiraIssueWebhook, TeamsApprovalCallback
├── chatops.py       — ChatOpsMessage, ChatOpsAction, ChatOpsProvider
├── triage.py        — TriageRequest, TriageResult, AITriageProvider
└── mappers.py       — Functions that transform raw events into canonical/command objects
```

### Key model transformations

```
Raw Graph notification JSON
  → GraphNotificationEnvelope  (ingress.py)
   → [ingress handler] validates signatures/tokens and filters by tenant/resource type
   → [normalize_event_body()] → SecurityEvent
   → [canonical_event_to_workflow_intent()] + route fan-out dispatcher
  → CanonicalEvent / SecurityEvent  passed to domain workflows
  → Domain models (TenantConfig, TenantSecrets, GraphUser, etc.) loaded in activities
```

The ingress handler's provider/event routing table and shared route registry are the central workflow mapping points for webhook-triggered starts.

---

## 8. End-to-End Event Walkthrough

### Scenario: Impossible Travel Alert

The following traces a risky sign-in notification through the entire system.

```
1. Microsoft Graph detects a risky sign-in and sends a change notification
   POST → AWS API Gateway /api/v1/graph/notifications/{tenant_id}

2. [L1] Lambda Authorizer
   - Validates HMAC on the outer HTTP request against SSM-stored tenant secret
   - Forwards validated request to the Lambda proxy

3. [L2] Ingress Lambda proxy — terraform/modules/ingress/src/ingress/handler.py
   - Deserialises body into GraphNotificationEnvelope
   - Validates Microsoft Defender bearer signature and optional Graph validation tokens
   - Verifies item `clientState` prefix matches path tenant
   - Maps resource to event type (`alert` or `impossible_travel`)
   - Normalizes payload and dispatches directly to routed workflow start(s)

4. [L3] ImpossibleTravelWorkflow (workflows/impossible_travel.py)
   a. activities.tenant.get_tenant_config() + get_tenant_secrets()  →  TenantConfig, TenantSecrets
   b. activities.graph_users.graph_get_user()                       →  GraphUser (display name, etc.)
   c. child: ThreatIntelEnrichmentWorkflow                          →  ThreatIntelResult (is_malicious, score)
   d. activities.connector_dispatch.connector_execute_action()      →  recent alerts for user
   e. child: TicketCreationWorkflow                                  →  TicketResult (ticket_id)
   f. child: HiTLApprovalWorkflow                                   →  (waits up to N hours for signal)
      - activities.hitl.issue_hitl_request()                        →  sends email + Teams adaptive card
      - workflow.wait_condition() on approval_signal                 →  blocks, durable Temporal timer
      - [analyst responds by signed email link or Jira callback]
      - GET /api/v1/hitl/respond or POST /api/v1/hitl/jira → ingress handler callback routes
      - ingress handler signals the waiting workflow with ApprovalDecision
   g. child: IncidentResponseWorkflow                               →  applies decision (disable user, etc.)
      - activities.connector_dispatch.connector_execute_action("isolate_device")
      - activities.graph_users.graph_disable_user()
      - activities.evidence.collect_evidence_bundle()               →  S3 evidence upload
      - activities.ticketing.close_ticket()
   h. activities.audit.create_audit_log()                           →  DynamoDB audit record

6. [L5] AWS Services consumed during the above:
   - SSM: tenant secrets for Graph, ticketing, threat intel
   - DynamoDB: audit record written, HITL token stored/retrieved
   - S3: evidence bundle uploaded
   - Graph API: user/alert/device reads + user disable action
   - Jira API: ticket created and closed
```

This flow demonstrates Temporal's key value: if any worker crashes during step 4b through 4h, Temporal replays from the last durable checkpoint on restart. The analyst's approval at step 4f can take hours — the workflow just waits with no held thread.

---

## 9. Temporal Patterns

### Determinism rule

Workflow code (`workflows/`) must be **deterministic and side-effect free**. This means:

- ✅ Call `workflow.execute_activity(...)` to perform any external operation.
- ✅ Call `workflow.execute_child_workflow(...)` to start a child workflow.
- ✅ Use `workflow.info()`, `workflow.logger`, and `workflow.now()` for context. (`workflow.now()` is safe because it returns the workflow's **logical time**, which is identical on every replay — unlike `datetime.now()`, which returns the real wall-clock time and produces a different value on replay, breaking determinism.)
- ❌ Never call `datetime.now()`, `random.random()`, `time.sleep()`, or any I/O directly.
- ❌ Never import non-deterministic code at the top level of a workflow file. Use `with workflow.unsafe.imports_passed_through():` for model imports.

### Activities

Activities are normal async Python functions annotated with `@activity.defn`. They can do anything: call APIs, write to databases, read files. They receive typed Pydantic inputs and return typed outputs.

Retry policy and timeout are always specified at the call site:

```python
result = await workflow.execute_activity(
    graph_get_user,
    args=[tenant_id, upn, secrets],
    start_to_close_timeout=timedelta(seconds=30),
    retry_policy=RetryPolicy(maximum_attempts=3),
)
```

### HITL via Signals

The `HiTLApprovalWorkflow` in `workflows/child/hitl_approval.py` demonstrates Temporal's signal pattern for human approval flows:

1. The workflow sends an approval request (email + Teams card with a button).
2. It then calls `await workflow.wait_condition(lambda: self._decision is not None, timeout=timedelta(hours=N))`.
3. When the analyst responds, ingress callback routes receive the decision (`/api/v1/hitl/respond` or `/api/v1/hitl/jira`).
4. `terraform/modules/ingress/src/ingress/handler.py` signals the workflow with the decision payload.
5. The workflow unblocks, receives the `ApprovalDecision`, and continues to incident response.
6. If the timer expires with no decision, the workflow applies the tenant's default timeout policy (e.g., escalate or auto-dismiss).

### Continue-as-New

Long-running loop workflows (`GraphSubscriptionManagerWorkflow`, `PollingManagerWorkflow`) use Temporal's `continue_as_new` pattern to prevent workflow history from growing unboundedly:

```python
# Call as a function — not raise — to restart the workflow with new state
workflow.continue_as_new(updated_state)
```

This closes the current workflow execution and starts a fresh one with the new state, preserving the workflow ID.

---

## 10. Connector Pattern

The connector layer (`connectors/`) provides a **provider-agnostic API** for all external integrations.

### Abstract interface (`connectors/base.py`)

```python
class BaseConnector(ABC):
    def __init__(self, tenant_id: str, secrets: TenantSecrets) -> None: ...
    async def fetch_events(self, query: dict) -> list[CanonicalEvent]: ...
    async def execute_action(self, action: str, payload: dict) -> dict: ...
    async def health_check(self) -> dict: ...
```

### Registry (`connectors/registry.py`)

All providers are registered in a dictionary mapping string keys to factory functions:

```python
_CONNECTOR_FACTORIES = {
    "microsoft_defender": _factory(MicrosoftGraphConnector),
    "jira": _factory(JiraConnector),
    "crowdstrike": _factory(CrowdStrikeConnector),  # stub
    ...
}
```

Activities call `get_connector(provider, tenant_id, secrets)` — the `provider` string comes from `TenantConfig.edr_provider` or `TenantConfig.ticketing_provider`, loaded from SSM. This means switching providers is a configuration change, not a code change.

### Stub providers (`connectors/stub_providers.py`)

Providers marked `[STUB]` implement `BaseConnector` but return non-success placeholder results. They hold the registry slot and serve as implementation templates.

---

## 11. Developer Extension Guide

### Adding a new connector provider

1. **Implement the connector** in a new file, e.g. `connectors/my_provider.py`, extending `BaseConnector`.
2. **Register it** in `connectors/registry.py`:
   ```python
   from connectors.my_provider import MyProviderConnector
   _CONNECTOR_FACTORIES["my_provider"] = _factory(MyProviderConnector)
   ```
3. **Add unit tests** in `tests/` that mock HTTP calls and assert the connector returns correct `CanonicalEvent` or result objects.
4. Update `README.md` Supported Connectors table.

### Adding a new workflow

1. **Create the workflow file**, e.g. `workflows/my_workflow.py`, with `@workflow.defn` on the class.
2. **Register it in `workers/run_worker.py`** by adding it to the `load_workflows()` function under the appropriate queue.
3. **Add a route** in `shared/models/mappers.py` if the workflow is triggered by a Graph notification resource type.
4. **Write tests** under `tests/` using Temporal's testing sandbox (`temporalio.testing`).
5. Update `README.md` Supported Workflows table.

### Adding a new activity

1. **Create or extend an activity module** in `activities/` with `@activity.defn` on the function.
2. **Register the activity** in `workers/run_worker.py` under the appropriate queue list.
3. **Use Pydantic models** from `shared/models/domain.py` for inputs and outputs.
4. **Never perform I/O** that bypasses SSM — always load secrets via `activities/tenant.get_tenant_secrets()`.
5. **Write tests** that mock the external dependency (boto3, Graph SDK, httpx).

### Adding a new tenant configuration field

1. **Add the field** to `TenantConfig` in `shared/models/domain.py` with a sensible default.
2. **Populate it** in `activities/tenant.py` from the SSM config path `/secamo/tenants/{tenant_id}/config/{field}`.
3. **Consume it** in the relevant workflow or activity via `config.my_new_field`.

---

## 12. Testing Approach

Tests live in `tests/` and follow `pytest` conventions. The project is configured with `asyncio_mode = auto` in `pytest.ini`, so async test functions work without explicit `@pytest.mark.asyncio` decorators.

```
tests/
├── test_models.py                    — Pydantic model validation and serialisation
├── test_ingress_mappers.py           — Mapper routing table correctness
├── test_graph_client.py              — Graph token cache behaviour
├── test_ingress_graph_notifications.py — Ingress Graph notification validation + dispatch behavior
├── test_graph_webhook_routing.py     — Graph notification to workflow routing
└── test_activities/                  — Activity-level unit tests with mocked clients
```

**Testing conventions:**

- External calls (Graph SDK, boto3, httpx) are always mocked via `pytest-mock` — tests never hit live APIs.
- Temporal workflow tests use the in-memory `WorkflowEnvironment` provided by `temporalio.testing`.
- Input and output fixtures use Pydantic models directly, not raw dicts.

Run tests with:

```bash
pytest
```

---

## 13. Infrastructure Overview

The `terraform/` folder contains two deployment targets:

### `environments/temporal-test/`

A single EC2 instance that runs the full Temporal + worker + ingress stack via Docker Compose. Used for integration validation and demos. The startup script `terraform/scripts/temporal-startup.sh` bootstraps all containers automatically on instance launch.

### `environments/poc/`

A production-grade PoC environment composed from reusable modules:

| Module             | Resources                                                         |
| ------------------ | ----------------------------------------------------------------- |
| `modules/vpc`      | VPC, subnets (public/private), Internet Gateway, fck-nat instance |
| `modules/security` | IAM roles, security groups, SSM parameter scaffolding             |
| `modules/compute`  | Worker EC2 instance with encrypted EBS                            |
| `modules/database` | RDS PostgreSQL (Temporal persistence store)                       |
| `modules/ingress`  | API Gateway HTTP API + Lambda authorizer + Lambda proxy           |
| `modules/storage`  | S3 evidence bucket + DynamoDB audit/subscription/HITL tables      |

### Local development with Docker Compose

```bash
# Start Temporal server, worker, and ingress locally
docker compose -f terraform/temporal-compose/docker-compose.yml up -d

# Start worker
python -m workers.run_worker

# Validate ingress behavior via focused tests
python -m pytest -q tests/test_ingress_graph_notifications.py

# Run tests
pytest
```

Environment variables required at minimum: `TEMPORAL_ADDRESS`, `TEMPORAL_NAMESPACE`. All others default to empty strings (disabling their respective features) or safe defaults.
