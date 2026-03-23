> DEPRECATED: This document is superseded by [graph_ingress/README.md](graph_ingress/README.md), [workflows/README.md](workflows/README.md), and [activities/README.md](activities/README.md).

# Graph Ingress Service (Implemented)

## Overview

This repository now contains a generic, multi-tenant Microsoft Graph ingress path that receives change notifications, validates tenant context, and routes events into Temporal workflows.

Implemented components:

- `graph_ingress/app.py`
- `graph_ingress/validator.py`
- `graph_ingress/dispatcher.py`
- `activities/graph_subscriptions.py`
- `workflows/graph_ingress_router.py`
- `workflows/graph_subscription_manager.py`
- model updates in `shared/models/`
- worker registration updates in `workers/run_worker.py`

## Runtime Flow

```text
Microsoft Graph
  -> GET /graph/notifications?validationToken=...
     (validation challenge)
  -> POST /graph/notifications
     (change notifications)

FastAPI graph ingress service
  -> GraphIngressValidator resolves tenant by:
     1) clientState format: secamo:{tenant_id}:{resource}
     2) fallback metadata lookup by subscription_id
  -> TemporalGraphIngressDispatcher starts GraphIngressRouterWorkflow

GraphIngressRouterWorkflow
  -> resolve_webhook_route(provider, resource)
  -> start routed child workflow with deterministic child workflow id

Existing domain workflows
  -> DefenderAlertEnrichmentWorkflow
  -> ImpossibleTravelWorkflow
```

## Subscription Lifecycle Flow

`GraphSubscriptionManagerWorkflow` runs per tenant and handles:

1. Read tenant config (`get_tenant_config`) and desired `graph_subscriptions`
2. Create missing Graph subscriptions (`create_graph_subscription`)
3. Remove stale subscriptions (`delete_graph_subscription`)
4. Renew expiring subscriptions (`renew_graph_subscription`)
5. Continue-as-new for long-running lifecycle safety

Supported signals:

- `subscription_list_changed`
- `offboard_tenant`

## Configuration

Environment variables:

- `TEMPORAL_ADDRESS`
- `TEMPORAL_NAMESPACE`
- `GRAPH_SUBSCRIPTIONS_TABLE` (recommended)
- `TENANT_TABLE_NAME` (for dynamic tenant registry)

Tenant configuration path:

- `/secamo/tenants/{tenant_id}/config/graph_subscriptions`

Supported formats:

1. JSON list (recommended)
2. Legacy string:
   - `resource:change1+change2:include_resource_data:expiration_hours`
   - example:
     - `security/alerts_v2:created+updated:false:24`

## Metadata Storage

Primary storage:

- DynamoDB table from `GRAPH_SUBSCRIPTIONS_TABLE`
- key: `subscription_id`

Fallback storage:

- SSM path `/secamo/tenants/{tenant_id}/subscriptions/{subscription_id}/...`

## New Route Mapping

Webhook routing (`resolve_webhook_route`) currently includes:

- `security/alerts` -> `DefenderAlertEnrichmentWorkflow` on `soc-defender`
- `security/alerts_v2` -> `DefenderAlertEnrichmentWorkflow` on `soc-defender`
- `auditLogs/signIns` -> `ImpossibleTravelWorkflow` on `soc-defender`
- `identityProtection/riskyUsers` -> `ImpossibleTravelWorkflow` on `soc-defender`

## Local Run

Start Temporal worker (existing):

```bash
python -m workers.run_worker
```

Start Graph ingress service:

```bash
uvicorn graph_ingress.app:app --host 0.0.0.0 --port 8081
```

Validation endpoint:

- `GET /graph/notifications?validationToken=abc123` -> `abc123` (text/plain)

Notification endpoint:

- `POST /graph/notifications`

## Tests Added

- `tests/test_graph_webhook_routing.py`
- `tests/test_graph_ingress_validator.py`
- `tests/test_activities/test_tenant_config.py` (graph_subscriptions parsing coverage)

## Notes

- The Graph ingress service responds quickly and dispatches routing work asynchronously to Temporal.
- Workflow and activity behavior follows deterministic/retryable Temporal patterns.
- Existing WF-02 and WF-05 workflows remain reusable and unchanged in intent.
