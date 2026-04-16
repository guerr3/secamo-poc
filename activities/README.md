# Activities - side-effect execution layer for Temporal workflows

> Temporal activities in this folder execute all external I/O for workflows.

## Responsibilities

- Execute provider API calls, AWS storage operations, and notification side effects.
- Translate transient/permanent failures into Temporal-safe retry semantics.
- Resolve tenant config and secrets at runtime.
- Keep workflow code deterministic by isolating non-deterministic work here.

## File Reference

| File                       | Responsibility                                                                            |
| -------------------------- | ----------------------------------------------------------------------------------------- |
| `__init__.py`              | Lazy export surface for activity symbols.                                                 |
| `_activity_errors.py`      | Shared retryability/error-classification helpers.                                         |
| `_tenant_secrets.py`       | Tenant secret-loading helper utility.                                                     |
| `audit.py`                 | Persist audit records to DynamoDB.                                                        |
| `communications.py`        | Send email/Teams notifications via connector-capability routing.                          |
| `edr.py`                   | EDR fetch/enrichment and remediation actions.                                             |
| `evidence.py`              | Persist evidence bundles to S3.                                                           |
| `hitl.py`                  | Dispatch HiTL approvals and store callback-token bindings.                                |
| `identity.py`              | IAM user lifecycle operations (get/create/update/delete/license/password/session revoke). |
| `onboarding.py`            | Tenant onboarding provisioning and registration activities.                               |
| `polling_dedup.py`         | Durable polling dedup tracking via processed-events table.                                |
| `provider_capabilities.py` | Generic connector fetch/action/health bridge activities.                                  |
| `risk.py`                  | Risk scoring helper activity.                                                             |
| `subscription.py`          | Graph subscription create/list/renew/delete and metadata persistence.                     |
| `tenant.py`                | Tenant validation, tenant config parsing, and tenant secret retrieval.                    |
| `threat_intel.py`          | Threat-intel lookup and fanout activities.                                                |
| `ticketing.py`             | Ticket create/update/close/get operations through connectors.                             |

## Key Concepts

- Retry-safe side effects: transient vendor/AWS failures remain retryable, caller/config errors are marked non-retryable.
- Idempotency first: activities tolerate at-least-once execution under Temporal retries.
- Tenant-scoped runtime: config/secrets are always resolved per tenant from SSM/path conventions.

## Usage

Workflows invoke activities via Temporal APIs instead of calling providers directly.

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
2. Keep the activity boundary typed and retry-safe.
3. Register the activity in `workers/run_worker.py` on the correct queue.
4. Add focused tests under `tests/test_activities/`.
5. Update this file table when module contents change.
