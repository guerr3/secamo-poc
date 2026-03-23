# Shared

> This folder contains shared runtime configuration, auth/util clients, model contracts, mappers, and tenant-aware provider factories used across ingress, activities, workflows, and tests.

## Files

| File | Purpose | Used By |
|------|---------|---------|
| `__init__.py` | Shared package marker. | Python module loading. |
| `config.py` | Central constants for Temporal address/namespace, queue names, sender email, evidence bucket, and audit table. | Workers, activities, ingress runtime. |
| `graph_client.py` | Graph/Defender token acquisition with in-memory token cache and refresh logic. | Graph activities and tests. |
| `ssm_client.py` | Thin SSM helper to fetch secrets or secret bundles by tenant path. | Tenant bootstrap, provider factory, activities. |
| `workflow_helpers.py` | `bootstrap_tenant(...)` helper that validates tenant and gathers config/secrets concurrently. | Parent workflows. |
| `models/__init__.py` | Re-exports model classes and mapping helpers. | Activities, workflows, ingress, tests. |
| `models/canonical.py` | Canonical event schema and normalized security context models. | Ingress mapping and workflow command generation. |
| `models/chatops.py` | ChatOps payload, action, provider protocol, and callback contracts. | ChatOps activity and webhook endpoints. |
| `models/commands.py` | Temporal command models (`StartWorkflowCommand`, `SignalWorkflowCommand`) and route metadata. | Mapper and dispatch logic. |
| `models/common.py` | Shared enums/helpers used by domain and canonical models. | Model layer internals. |
| `models/domain.py` | Core domain models for tenant config/secrets, ticketing, risk, HITL, incidents, and workflow requests/results. | Activities and workflows. |
| `models/ingress.py` | Raw ingress envelope and Graph notification envelope schemas. | `graph_ingress` service and workflow router. |
| `models/mappers.py` | Provider/webhook mapping, route resolution, and canonical/security event transformation. | Ingress routing, polling routing, tests. |
| `models/provider_events.py` | Provider-specific event wrappers (Defender, Jira, Teams callback). | Mapper pipeline. |
| `models/triage.py` | AI triage request/result models and provider protocol contract. | AI triage activity and provider implementations. |
| `providers/__init__.py` | Provider package exports. | Activity and ingress provider loading. |
| `providers/factory.py` | Tenant runtime config loading from SSM plus cached AI/ChatOps provider instance resolution. | AI triage activity and ChatOps webhook/dispatch code. |
| `providers/ai/__init__.py` | AI provider exports. | Provider factory. |
| `providers/ai/azure_openai.py` | Azure OpenAI triage provider with PII redaction and strict JSON response parsing. | `providers/factory.py`, triage activity. |
| `providers/chatops/__init__.py` | ChatOps provider exports. | Provider factory. |
| `providers/chatops/ms_teams.py` | Teams adaptive-card sender + signature validation + callback parsing. | ChatOps activity and webhook callback endpoint. |
| `providers/chatops/slack.py` | Slack message sender (webhook or bot token), signature validation, callback parsing. | ChatOps activity and webhook callback endpoint. |

## How It Fits

Everything in this folder is a dependency layer for [../activities/README.md](../activities/README.md), [../workflows/README.md](../workflows/README.md), and [../graph_ingress/README.md](../graph_ingress/README.md). The model and mapper pipeline defines how provider payloads become normalized security events and workflow commands, while provider factory code selects concrete AI/ChatOps implementations at runtime from tenant configuration. Queue constants and runtime defaults in `config.py` are consumed by [../workers/README.md](../workers/README.md).

## Notes / Extension Points

- `providers/factory.py` has explicit unimplemented paths for `aws_bedrock` and `local` AI provider types (`NotImplementedError`), so these provider types are currently `[STUB]` at runtime.
- Provider and tenant config values are loaded from SSM under `/secamo/tenants/{tenant_id}/config/*` and secret paths under `/secamo/tenants/{tenant_id}/{secret_type}/*`.
- Keep mapper routing tables synchronized with workflow names and queue names when adding new provider event types.
