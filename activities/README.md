# Activities - side-effect execution layer for Temporal workflows

> Temporal activities in this folder perform all external I/O for workflow orchestration.

## Responsibilities

- Execute provider API calls, AWS storage operations, and notification side effects.
- Enforce retry-safe error translation between external failures and Temporal semantics.
- Load tenant-specific config and secrets for downstream actions.
- Keep workflow code deterministic by isolating non-deterministic work here.

## File Reference

| File                       | Responsibility                                                                    |
| -------------------------- | --------------------------------------------------------------------------------- |
| `__init__.py`              | Lazy export surface for activity symbols.                                         |
| `_activity_errors.py`      | Shared activity error helpers and classification utilities.                       |
| `audit.py`                 | Persist audit records to DynamoDB.                                                |
| `chatops.py`               | Send interactive ChatOps notifications.                                           |
| `provider_capabilities.py` | Provider-agnostic capability bridge for connector fetch/action/health operations. |
| `evidence.py`              | Persist evidence bundles to S3.                                                   |
| `graph_alerts.py`          | Query and enrich Defender alert data via Graph.                                   |
| `graph_devices.py`         | Execute device-level actions and lookups.                                         |
| `graph_signin.py`          | Query risky sign-in and identity risk context.                                    |
| `graph_subscriptions.py`   | Manage Graph webhook subscription lifecycle and metadata.                         |
| `graph_users.py`           | Execute user lifecycle operations in Graph.                                       |
| `hitl.py`                  | Issue HiTL approvals and manage callback token flow.                              |
| `hitl_renderers.py`        | Render HiTL email/body content templates.                                         |
| `notify_email.py`          | Send email notifications through Graph mail APIs.                                 |
| `notify_teams.py`          | Send Teams notifications and adaptive cards.                                      |
| `README.md`                | Module documentation.                                                             |
| `risk.py`                  | Compute risk scores from enrichment context.                                      |
| `tenant.py`                | Resolve tenant config, secrets, and tenant validity.                              |
| `threat_intel.py`          | Execute threat intel lookups.                                                     |
| `ticketing.py`             | Create/update/close/get ticket operations through connectors.                     |
| `triage.py`                | Execute AI triage provider analysis.                                              |
| `__pycache__/`             | Generated Python bytecode cache directory.                                        |

## Key Concepts

- Retry semantics: activities map transient failures to retryable outcomes and preserve non-retryable boundaries where caller/config/data is invalid.
- Idempotency: write and action paths are designed to tolerate at-least-once execution under Temporal retries.
- Tenant bootstrap: tenant configuration and secrets are resolved at runtime using tenant-scoped SSM and table paths.

## Usage

Workflows invoke activities through Temporal APIs instead of calling providers directly.

```python
result = await workflow.execute_activity(
    some_activity,
    args=[tenant_id, payload],
    start_to_close_timeout=timedelta(seconds=30),
)
```

## Testing

```bash
python -m pytest -q tests/test_activities
```

## Extension Points

1. Add a new activity module or function under `activities/`.
2. Annotate it with the Temporal activity definition pattern used in this codebase.
3. Register it in `workers/run_worker.py` on the correct queue.
4. Add focused tests under `tests/test_activities/`.
5. Update this file table if a new module is added.
