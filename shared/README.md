# Shared

> This folder contains shared runtime configuration, model contracts, ingress/auth/normalization/routing/temporal boundaries, and tenant-aware provider factories used across ingress, activities, workflows, and tests.

## Files

| File                                  | Purpose                                                                                                        | Used By                                                     |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| `__init__.py`                         | Shared package marker.                                                                                         | Python module loading.                                      |
| `config.py`                           | Central constants for Temporal address/namespace, queue names, sender email, evidence bucket, and audit table. | Workers, activities, ingress runtime.                       |
| `graph_client.py`                     | Graph/Defender token acquisition with in-memory token cache and refresh logic.                                 | Graph activities and tests.                                 |
| `ssm_client.py`                       | Thin SSM helper to fetch secrets or secret bundles by tenant path.                                             | Tenant bootstrap, provider factory, activities.             |
| `workflow_helpers.py`                 | `bootstrap_tenant(...)` helper that validates tenant and gathers config/secrets concurrently.                  | Parent workflows.                                           |
| `approval/contracts.py`               | Typed callback signal contracts (`ApprovalSignal`, discriminated signal payload union).                        | HITL callback normalization and signal dispatch boundaries. |
| `approval/callbacks.py`               | Channel callback normalization (email/jira/slack/teams) to shared `ApprovalSignal`.                            | Callback ingestion paths and tests.                         |
| `approval/token_store.py`             | DynamoDB token store and TTL policy (`HITL_TOKEN_TTL_SECONDS`, default `900`).                                 | HITL token creation/consume flows.                          |
| `auth/contracts.py`                   | Validator request/result contracts and secret resolver/validator protocols.                                    | Auth registry and validators.                               |
| `auth/registry.py`                    | Provider/channel auth validator registry with fail-closed behavior.                                            | Ingress auth boundaries and tests.                          |
| `auth/secrets.py`                     | Cached SSM/JWKS resolution primitives for validator implementations.                                           | Auth validators.                                            |
| `auth/validators/*`                   | Concrete validators (Microsoft Graph JWT, HMAC-SHA256, Slack signature).                                       | Auth registry defaults.                                     |
| `ingress/contracts.py`                | Transport-agnostic ingress request/context/result contracts.                                                   | Ingress stage boundaries and tests.                         |
| `ingress/pipeline.py`                 | Pipeline stage protocols (`Authenticate`, `Normalize`, `Route`, `Dispatch`).                                   | Ingress orchestration adapters.                             |
| `ingress/errors.py`                   | Typed ingress error codes and exception wrapper.                                                               | Ingress handlers and tests.                                 |
| `normalization/contracts.py`          | Public `WorkflowIntent` contract for post-normalization output.                                                | Routing and temporal fan-out boundaries.                    |
| `normalization/normalizers.py`        | Canonical event to `WorkflowIntent` normalization helper(s).                                                   | Ingress dispatchers.                                        |
| `normalization/internal_canonical.py` | Internal-only canonical wrapper used by normalization internals.                                               | Normalization module internals.                             |
| `routing/contracts.py`                | Route and fan-out dispatch report contracts (`WorkflowRoute`, `DispatchReport`).                               | Route registry and dispatch adapters.                       |
| `routing/registry.py`                 | In-memory route registry and best-effort fan-out behavior.                                                     | Temporal route dispatching.                                 |
| `routing/defaults.py`                 | Code-defined default route mappings by provider/event type.                                                    | Ingress/Graph dispatchers.                                  |
| `temporal/signal_gateway.py`          | Transport-agnostic typed signal gateway for workflow signaling.                                                | Callback signaling boundaries.                              |
| `temporal/dispatcher.py`              | Route fan-out dispatcher abstraction for workflow start operations.                                            | Ingress and Graph dispatchers.                              |
| `models/__init__.py`                  | Re-exports model classes and mapping helpers.                                                                  | Activities, workflows, ingress, tests.                      |
| `models/canonical.py`                 | Canonical event schema and normalized security context models.                                                 | Ingress mapping and workflow command generation.            |
| `models/chatops.py`                   | ChatOps payload, action, provider protocol, and callback contracts.                                            | ChatOps activity and webhook endpoints.                     |
| `models/commands.py`                  | Temporal command models (`StartWorkflowCommand`, `SignalWorkflowCommand`) and route metadata.                  | Mapper and dispatch logic.                                  |
| `models/common.py`                    | Shared enums/helpers used by domain and canonical models.                                                      | Model layer internals.                                      |
| `models/domain.py`                    | Core domain models for tenant config/secrets, ticketing, risk, HITL, incidents, and workflow requests/results. | Activities and workflows.                                   |
| `models/ingress.py`                   | Raw ingress envelope and Graph notification envelope schemas.                                                  | Ingress Lambda handlers and workflow router.                |
| `models/mappers.py`                   | Legacy + shared canonical/security transformation helpers still used during migration.                         | Ingress and workflow compatibility paths, tests.            |
| `models/provider_events.py`           | Provider-specific event wrappers (Defender, Jira, Teams callback).                                             | Mapper pipeline.                                            |
| `models/triage.py`                    | AI triage request/result models and provider protocol contract.                                                | AI triage activity and provider implementations.            |
| `providers/__init__.py`               | Provider package exports.                                                                                      | Activity and ingress provider loading.                      |
| `providers/factory.py`                | Tenant runtime config loading from SSM plus cached AI/ChatOps provider instance resolution.                    | AI triage activity and ChatOps webhook/dispatch code.       |
| `providers/ai/__init__.py`            | AI provider exports.                                                                                           | Provider factory.                                           |
| `providers/ai/azure_openai.py`        | Azure OpenAI triage provider with PII redaction and strict JSON response parsing.                              | `providers/factory.py`, triage activity.                    |
| `providers/chatops/__init__.py`       | ChatOps provider exports.                                                                                      | Provider factory.                                           |
| `providers/chatops/ms_teams.py`       | Teams adaptive-card sender + signature validation + callback parsing.                                          | ChatOps activity and webhook callback endpoint.             |
| `providers/chatops/slack.py`          | Slack message sender (webhook or bot token), signature validation, callback parsing.                           | ChatOps activity and webhook callback endpoint.             |

## How It Fits

Everything in this folder is a dependency layer for [../activities/README.md](../activities/README.md), [../workflows/README.md](../workflows/README.md), and [../terraform/modules/ingress/src/ingress/handler.py](../terraform/modules/ingress/src/ingress/handler.py). Ingress and graph adapters authenticate input, normalize to `WorkflowIntent`, resolve `WorkflowRoute` entries, and dispatch via transport-agnostic temporal boundaries. Provider factory code continues to select concrete AI/ChatOps implementations at runtime from tenant configuration. Queue constants and runtime defaults in `config.py` are consumed by [../workers/README.md](../workers/README.md).

## Notes / Extension Points

- `providers/factory.py` has explicit unimplemented paths for `aws_bedrock` and `local` AI provider types (`NotImplementedError`), so these provider types are currently `[STUB]` at runtime.
- Provider and tenant config values are loaded from SSM under `/secamo/tenants/{tenant_id}/config/*` and secret paths under `/secamo/tenants/{tenant_id}/{secret_type}/*`.
- Keep route mappings in `shared/routing/defaults.py` synchronized with workflow names/task queues, and keep normalization behavior in `shared/normalization/normalizers.py` aligned with route keys.
