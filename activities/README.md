# Activities

> This folder contains Temporal activities that perform external side effects such as Graph operations, ticketing actions, notifications, audit writes, and tenant configuration retrieval.

## Files

| File | Purpose | Used By |
|------|---------|---------|
| `__init__.py` | Lazy exports for activity symbols to avoid import-time side effects. | Worker imports and module-level activity access. |
| `audit.py` | Writes audit records to DynamoDB with workflow context metadata. | IAM and SOC workflows. |
| `chatops.py` | Sends interactive alert payloads through tenant-specific ChatOps providers. | `workflows/defender_alert_enrichment.py`. |
| `connector_dispatch.py` | Provider-agnostic activities for `fetch_events`, `execute_action`, health checks, and threat-intel fanout. | Polling manager, ticketing, enrichment, incident workflows. |
| `evidence.py` | Persists evidence bundle payloads to S3 and returns a reference URL. | `workflows/child/incident_response.py`. |
| `graph_alerts.py` | Reads and enriches Defender alerts through Microsoft Graph endpoints. | `workflows/child/alert_enrichment.py`, SOC flows. |
| `graph_devices.py` | Device-level Graph/Defender actions (isolate, unisolate, scan, details, compliance list). | Alert enrichment and incident response workflows. |
| `graph_signin.py` | Identity risk and sign-in timeline operations for impossible-travel paths. | `workflows/impossible_travel.py`. |
| `graph_subscriptions.py` | Graph subscription create/renew/delete/list and metadata persistence. | `workflows/graph_subscription_manager.py`, ingress tenant resolution fallback. |
| `graph_users.py` | User lifecycle actions in Graph (get/create/update/delete/revoke/license/password). | `workflows/iam_onboarding.py`, `workflows/child/user_deprovisioning.py`. |
| `hitl.py` | Issues HITL approvals, stores/retrieves approval tokens, and builds response links. | `workflows/child/hitl_approval.py`. |
| `hitl_renderers.py` | HTML/body rendering helpers for HITL approval messages. | `activities/hitl.py`. |
| `notify_email.py` | Sends email notifications through Graph Mail APIs. | SOC and IAM notification points. |
| `notify_teams.py` | Sends Teams text and adaptive card messages. | SOC notifications and HITL prompts. |
| `risk.py` | Computes risk score and risk level from severity, intel, compliance, and enrichment context. | `workflows/child/alert_enrichment.py`. |
| `tenant.py` | Resolves tenant validity, config, and secrets from SSM/DynamoDB paths. | Most workflows and activity bootstrap paths. |
| `threat_intel.py` | Threat intel lookup activity (current implementation focuses on VirusTotal inputs). | `workflows/child/threat_intel_enrichment.py`. |
| `ticketing.py` | Ticket lifecycle actions (create/update/close/get) via connector dispatch. | Ticket child workflows and SOC orchestration. |
| `triage.py` | Executes AI triage provider analysis and returns normalized triage recommendations. | `workflows/defender_alert_enrichment.py`. |

## How It Fits

Workflows in [../workflows/README.md](../workflows/README.md) call these functions through `workflow.execute_activity(...)` to keep workflow code deterministic while side effects happen in activity workers. Most activity operations depend on shared contracts from [../shared/README.md](../shared/README.md) and provider implementations routed by [../connectors/README.md](../connectors/README.md). This folder is registered to task queues by [../workers/README.md](../workers/README.md).

## Notes / Extension Points

- Keep activity inputs/outputs on Pydantic models from `shared/models` so workflow boundaries stay stable.
- `threat_intel.py` currently has limited provider depth compared with configured provider keys; additional providers should be added via connector dispatch.
- Tenant secret lookups follow `/secamo/tenants/{tenant_id}/{secret_type}/{key}` and should not be bypassed.
