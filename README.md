# Root

> The repository root ties together Temporal workflows, activity implementations, ingress services, connector adapters, and Terraform deployment assets for a multi-tenant security orchestrator.

## Files

| File                                     | Purpose                                                                                                      | Used By                                                                      |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| `README.md`                              | Repository-level architecture, workflow, connector, and runtime guide.                                       | Engineers onboarding to the codebase.                                        |
| `requirements.txt`                       | Python dependency lock list for runtime and tests.                                                           | Local development, Docker image build, CI test runs.                         |
| `pytest.ini`                             | Pytest configuration (`asyncio_mode = auto`).                                                                | `pytest` test runner.                                                        |
| `Dockerfile`                             | Builds the worker runtime image and starts `python -m workers.run_worker`.                                   | Temporal test compose stack and EC2/container deployments.                   |
| `payload.json`                           | Sample ingress payload for local/manual workflow trigger tests.                                              | Manual API and workflow validation.                                          |
| `activities/`                            | Temporal activity layer: Graph, ticketing, notifications, audit, tenant config, connector dispatch.          | `workers/run_worker.py` queue registrations and workflow activity execution. |
| `workflows/`                             | Parent workflows that orchestrate IAM, SOC, subscriptions, and polling loops.                                | Temporal workers and ingress dispatchers.                                    |
| `workflows/child/`                       | Child workflows for enrichment, ticketing, HITL, incident response, and user deprovisioning.                 | Parent workflows in `workflows/`.                                            |
| `connectors/`                            | Provider adapter interface + concrete/stub providers.                                                        | `activities/connector_dispatch.py`, ticketing/risk workflows.                |
| `workers/`                               | Worker bootstrap and queue-scoped registration logic.                                                        | Runtime process entrypoint.                                                  |
| `terraform/modules/ingress/src/ingress/` | API Gateway proxy Lambda ingress handlers for provider/internal webhook intake and workflow dispatch.        | HTTP webhook endpoint and workflow start path.                               |
| `shared/`                                | Shared settings, auth clients, ingress/normalization/routing contracts, Pydantic models, provider factories. | Activities, workflows, ingress, connectors, tests.                           |
| `terraform/`                             | IaC for PoC and temporal-test infrastructure.                                                                | Deployment and environment provisioning.                                     |
| `tests/`                                 | Unit tests for selected shared models, activities, ingress routing, and tenant config behavior.              | CI/local test execution.                                                     |

## Architecture Overview

```text
Incoming Webhook/Event
  -> [L1] API Gateway + Lambda Authorizer (tenant auth/identity)
  -> [L2] Ingress Service (normalize payload + dispatch)
  -> [L3] Temporal Workflows (deterministic orchestration)
  -> [L4] Activity + Connector Layer (provider-specific actions)
  -> [L5] AWS Services (SSM, S3, DynamoDB, EC2/RDS)
```

## Supported Workflows

| Workflow                           | File                                         | Trigger Source                                                               | Core Actions                                                                                                              | Queue          | Status |
| ---------------------------------- | -------------------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | -------------- | ------ |
| `IamOnboardingWorkflow`            | `workflows/iam_onboarding.py`                | IAM ingress/polling lifecycle events                                         | Create/update/delete/reset Graph users, optional license assignment, audit logging, optional poller child startup.        | `iam-graph`    | Active |
| `DefenderAlertEnrichmentWorkflow`  | `workflows/defender_alert_enrichment.py`     | Routed ingress intent fan-out for `defender.alert` notifications             | Optional threat intel child, alert enrichment child, optional ticket child, Teams notify, audit log.                      | `soc-defender` | Active |
| `ImpossibleTravelWorkflow`         | `workflows/impossible_travel.py`             | Routed ingress intent fan-out for `defender.impossible_travel` notifications | User enrichment, optional threat intel child, ticket child, HITL approval child, incident response child.                 | `soc-defender` | Active |
| `GraphSubscriptionManagerWorkflow` | `workflows/graph_subscription_manager.py`    | Scheduled/manual Temporal start                                              | Reconciles desired Graph subscriptions, renews expiring subscriptions, handles signals and continue-as-new loop.          | `soc-defender` | Active |
| `PollingManagerWorkflow`           | `workflows/polling_manager.py`               | Started by onboarding workflow per polling provider                          | Fetches provider events through connector dispatch, maps routes, starts downstream child workflows, continue-as-new loop. | `poller`       | Active |
| `AlertEnrichmentWorkflow`          | `workflows/child/alert_enrichment.py`        | Child of defender enrichment workflow                                        | Connector enrichment + device/user context + risk score calculation.                                                      | `soc-defender` | Active |
| `ThreatIntelEnrichmentWorkflow`    | `workflows/child/threat_intel_enrichment.py` | Child of defender/impossible-travel workflows                                | Fanout threat intel lookup activity.                                                                                      | `soc-defender` | Active |
| `TicketCreationWorkflow`           | `workflows/child/ticket_creation.py`         | Child of defender/impossible-travel workflows                                | Creates ticket through provider-agnostic connector activity.                                                              | `soc-defender` | Active |
| `HiTLApprovalWorkflow`             | `workflows/child/hitl_approval.py`           | Child of impossible-travel workflow                                          | Sends approval request, waits for signal, handles timeout policy and optional escalation/isolation action.                | `soc-defender` | Active |
| `IncidentResponseWorkflow`         | `workflows/child/incident_response.py`       | Child of impossible-travel workflow                                          | Applies analyst decision (dismiss/isolate/disable user) and optional evidence collection.                                 | `soc-defender` | Active |
| `UserDeprovisioningWorkflow`       | `workflows/child/user_deprovisioning.py`     | Child of onboarding workflow on delete action                                | Revokes sessions and deletes user in Graph.                                                                               | `iam-graph`    | Active |

## Supported Connectors

| Connector Key        | File/Class                                                     | Type                              | Status   |
| -------------------- | -------------------------------------------------------------- | --------------------------------- | -------- |
| `microsoft_defender` | `connectors/microsoft_defender.py` / `MicrosoftGraphConnector` | EDR + Graph security data/actions | Active   |
| `jira`               | `connectors/jira.py` / `JiraConnector`                         | Ticketing                         | Active   |
| `crowdstrike`        | `connectors/stub_providers.py` / `CrowdStrikeConnector`        | EDR                               | `[STUB]` |
| `sentinelone`        | `connectors/stub_providers.py` / `SentinelOneConnector`        | EDR                               | `[STUB]` |
| `halo_itsm`          | `connectors/stub_providers.py` / `HaloItsmConnector`           | Ticketing                         | `[STUB]` |
| `servicenow`         | `connectors/stub_providers.py` / `ServiceNowConnector`         | Ticketing                         | `[STUB]` |
| `virustotal`         | `connectors/stub_providers.py` / `VirusTotalConnector`         | Threat intel                      | `[STUB]` |
| `abuseipdb`          | `connectors/stub_providers.py` / `AbuseIpdbConnector`          | Threat intel                      | `[STUB]` |
| `misp`               | `connectors/stub_providers.py` / `MispConnector`               | Threat intel sharing              | `[STUB]` |

## Environment Variables Reference

| Variable                     | Default                | Used In                                                         | Purpose                                                                        |
| ---------------------------- | ---------------------- | --------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `TEMPORAL_ADDRESS`           | `temporal:7233`        | `shared/config.py`, worker and ingress Temporal clients         | Temporal frontend address.                                                     |
| `TEMPORAL_NAMESPACE`         | `default`              | `shared/config.py`, worker and ingress Temporal clients         | Temporal namespace for workflow execution.                                     |
| `SECAMO_SENDER_EMAIL`        | `noreply@secamo.local` | `shared/config.py`, email notification activity                 | Sender identity for Graph mail notifications.                                  |
| `EVIDENCE_BUCKET_NAME`       | empty                  | `shared/config.py`, evidence activity                           | S3 bucket for evidence bundles.                                                |
| `AUDIT_TABLE_NAME`           | empty                  | `shared/config.py`, audit activity                              | DynamoDB table for audit records.                                              |
| `TENANT_TABLE_NAME`          | empty                  | `activities/tenant.py`                                          | DynamoDB table for active tenant discovery fallback.                           |
| `GRAPH_SUBSCRIPTIONS_TABLE`  | empty                  | `activities/graph_subscriptions.py`                             | DynamoDB table for Graph subscription metadata lookup.                         |
| `HITL_TOKEN_TABLE`           | empty                  | `activities/hitl.py`, Terraform ingress handler                 | DynamoDB table that stores approval tokens.                                    |
| `HITL_TOKEN_TTL_SECONDS`     | `900`                  | `shared/approval/token_store.py`, Terraform ingress handler env | TTL for HITL callback token validity in seconds.                               |
| `HITL_NAME_PREFIX`           | `secamo-temporal-test` | `activities/hitl.py`                                            | Name prefix used for HITL response URLs.                                       |
| `GRAPH_NOTIFICATION_APP_IDS` | empty                  | `terraform/modules/ingress/src/ingress/handler.py`              | Comma-separated app IDs accepted for Graph rich notification token validation. |
| `LOG_LEVEL`                  | `INFO`                 | `terraform/modules/ingress/src/authorizer/handler.py`           | Lambda authorizer logging level.                                               |
| `CACHE_TTL_SECONDS`          | `300`                  | `terraform/modules/ingress/src/authorizer/handler.py`           | Authorizer credential cache TTL.                                               |

## Quick Start

1. Create and activate a Python 3.11 virtual environment.
2. Install dependencies with `pip install -r requirements.txt`.
3. Start a Temporal stack (for local test, use `docker compose -f terraform/temporal-compose/docker-compose.yml up -d`).
4. Export required runtime variables at minimum: `TEMPORAL_ADDRESS`, `TEMPORAL_NAMESPACE`; optionally set storage/audit/tenant table variables.
5. Start workers with `python -m workers.run_worker`.
6. Start ingress Lambda path for local validation via tests under `tests/` or deploy API Gateway + ingress module from `terraform/modules/ingress/`.
7. Run tests with `pytest`.

## How It Fits

The root folder connects all runtime layers: ingress receives and validates events, workflows orchestrate deterministic execution, activities perform side effects, connectors isolate provider APIs, and Terraform deploys the infrastructure those layers depend on. Folder-level details are documented in [activities/README.md](activities/README.md), [workflows/README.md](workflows/README.md), [connectors/README.md](connectors/README.md), [workers/README.md](workers/README.md), [shared/README.md](shared/README.md), [terraform/README.md](terraform/README.md), and [tests/README.md](tests/README.md).

## Notes / Extension Points

- Tenant config and secrets are loaded from SSM paths under `/secamo/tenants/{tenant_id}/...`; avoid hardcoded credentials.
- `workflows/iam_onboarding.py` contains a TODO hardcoded temporary password path that should be replaced with secure password generation.
- Connector keys are centrally registered in `connectors/registry.py`; new provider support requires implementation plus registration.
