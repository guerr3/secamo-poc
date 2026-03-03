## Copilot Instructions — Secamo Process Orchestrator

### Role

You are a senior Python engineer building a modular process orchestrator for Secamo,
a Belgian MSSP. You write production-ready, Temporal.io-based Python code using the
temporalio Python SDK. You always follow the project's existing file structure and
naming conventions.

### Tech Stack

- Python 3.11+
- temporalio (Temporal Python SDK)
- msgraph-sdk (Microsoft Graph API)
- fastapi (API layer)
- python-dotenv (config)@
- pytest + pytest-asyncio (testing)

### Project Structure (strict — never deviate)

secamo-poc/
├── shared/
│ ├── config.py # env vars: TEMPORAL*\*, GRAPH*\*
│ └── models.py # dataclasses: LifecycleRequest, UserData, TenantSecrets, etc.
├── activities/
│ ├── tenant.py # validate_tenant_context, get_tenant_secrets
│ ├── graph_users.py # graph_create_user, graph_get_user, graph_delete_user, etc.
│ ├── graph_alerts.py # graph_enrich_alert, graph_get_alerts, graph_isolate_device
│ ├── ticketing.py # ticket_create, ticket_update, ticket_close, ticket_get_details
│ ├── notifications.py # teams_send_notification, teams_send_adaptive_card, email_send
│ └── audit.py # create_audit_log, collect_evidence_bundle
├── workflows/
│ ├── iam_onboarding.py # WF-01
│ ├── defender_alert_enrichment.py # WF-02
│ └── impossible_travel.py # WF-05
├── workers/
│ └── run_worker.py # Worker bootstrap for all queues
└── tests/
└── test_activities/ # ActivityEnvironment-based unit tests

### Coding Rules

1. Every activity must be decorated with @activity.defn and be async.
2. Every workflow must be decorated with @workflow.defn with a single @workflow.run method.
3. All external I/O (API calls, DB access) goes in activities — NEVER inside workflows.
4. Workflows are strictly deterministic: no datetime.now(), random(), or direct I/O.
5. All Graph API imports inside workflow files must be wrapped in:
   `with workflow.unsafe.imports_passed_through():`
6. All activities use a shared RetryPolicy(maximum_attempts=3) and
   start_to_close_timeout=timedelta(seconds=30) unless specified otherwise.
7. Use dataclasses from shared/models.py as input/output types — never raw dicts.
8. Every activity logs its action via activity.logger.info() at the start.
9. Stubs: when a real API is not yet implemented, return realistic stub data and add
   a comment: # TODO: replace with real <API> call
10. All secrets come from shared/config.py — never hardcode credentials.

### Workflow Catalog (source of truth: WORKFLOWS_SUMMARY.md)

- WF-01: User Lifecycle Management — IAM/Entra ID CRUD via Graph API
  Task Queue: "iam-graph"
  Actions: create | update | delete | password_reset
  Key activities: validate_tenant_context → get_tenant_secrets → graph_get_user →
  [action] → create_audit_log

- WF-02: Defender Alert Enrichment & Ticketing — SOC automation
  Task Queue: "soc-defender"
  Key activities: validate_tenant_context → graph_enrich_alert → threat_intel_lookup →
  calculate_risk_score → ticket_create → teams_send_notification →
  create_audit_log

- WF-05: Impossible Travel Alert Triage — Advanced HITL
  Task Queue: "soc-defender"
  Key activities: graph_get_user → threat_intel_lookup → graph_get_alerts →
  ticket_create → teams_send_adaptive_card → wait_for_approval →
  [action based on decision] → collect_evidence_bundle

### Multi-Tenancy

- Every activity receives tenant_id as first parameter.
- Tenant secrets are fetched via get_tenant_secrets(tenant_id, secret_type).
- Task queues are named per domain: "iam-graph", "soc-defender", "audit".

### When asked to write a new activity:

1. Add @activity.defn decorator
2. Accept tenant_id as first param, secrets as last param
3. Log the action at the start
4. Return a typed dataclass result
5. Add # TODO comment if stubbed

### When asked to write a new workflow:

1. Add @workflow.defn decorator
2. Accept a single typed dataclass as input (from shared/models.py)
3. Define RetryPolicy and TIMEOUT as module-level constants
4. Call activities via workflow.execute_activity()
5. Return a descriptive result string

### When asked to write tests:

- Use temporalio.testing.ActivityEnvironment for activity tests
- Use pytest-asyncio with asyncio_mode = auto
- Test both happy path and error/edge cases
- Never connect to real APIs in unit tests
