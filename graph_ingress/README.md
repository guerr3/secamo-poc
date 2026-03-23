# Graph Ingress

> This folder implements a FastAPI ingress service that validates Microsoft Graph notifications, resolves tenant context, and dispatches routed workflows/signals into Temporal.

## Files

| File | Purpose | Used By |
|------|---------|---------|
| `__init__.py` | Package marker. | Python module loading. |
| `app.py` | FastAPI app with `/graph/notifications` (challenge + notification receive), `/healthz`, and ChatOps router mount. | Uvicorn launcher and ingress container runtime. |
| `chatops_webhook.py` | Handles `/chatops/action` callback payloads, validates signatures via provider implementations, and signals workflow handles. | ChatOps buttons/cards from Teams and Slack. |
| `dispatcher.py` | Starts `GraphIngressRouterWorkflow` on the SOC queue using Temporal client. | `app.py` dispatch path after validation. |
| `launcher.py` | Uvicorn startup entrypoint, reading `GRAPH_INGRESS_HOST` and `GRAPH_INGRESS_PORT`. | Local run and container command. |
| `validator.py` | Resolves tenant from `clientState` or Graph subscription metadata table and filters unsupported notifications. | `app.py` notification intake flow. |

## How It Fits

This service is the HTTP boundary for Microsoft Graph webhook payloads before orchestration begins in [../workflows/README.md](../workflows/README.md). It depends on shared models/mappers from [../shared/README.md](../shared/README.md) and dispatches only validated events into Temporal workers described in [../workers/README.md](../workers/README.md). ChatOps callbacks reuse provider validation logic from [../shared/README.md](../shared/README.md#files) and signal already-running workflows.

## Notes / Extension Points

- `validator.py` supports both clientState-based tenant resolution and optional DynamoDB subscription metadata lookup via `GRAPH_SUBSCRIPTIONS_TABLE`.
- New webhook resources require route updates in `shared/models/mappers.py` so `GraphIngressRouterWorkflow` can start the correct workflow.
- Keep callback verification strict; provider signatures are validated before workflow signals are sent.
