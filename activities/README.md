# Activities

Temporal activities are the side-effect layer of this repository.
All non-deterministic work (AWS calls, provider APIs, notifications, storage writes) must stay here and out of workflow code.

## What This Module Owns

- Tenant runtime access: tenant validation, tenant config loading, tenant secrets loading.
- Provider side effects: EDR fetch/actions, identity actions, ticketing actions, threat-intel fanout.
- Messaging side effects: HiTL dispatch, email sending, chatops notifications.
- Persistence side effects: audit log writes, evidence bundle writes, polling dedup state writes.

## Activity Map

| File                       | Responsibility                                                                  |
| -------------------------- | ------------------------------------------------------------------------------- |
| `tenant.py`                | Tenant validation plus config/secrets retrieval from SSM and tenant table paths |
| `onboarding.py`            | Tenant onboarding persistence/bootstrap activities                              |
| `identity.py`              | User lifecycle operations (create/update/delete/reset/revoke/license)           |
| `edr.py`                   | Defender/EDR fetch, enrichment, and remediation actions                         |
| `subscription.py`          | Graph subscription create/list/renew/delete and metadata helpers                |
| `polling_dedup.py`         | Durable dedup writes for polled provider events                                 |
| `threat_intel.py`          | Threat-intel lookups and provider fanout                                        |
| `risk.py`                  | Risk score calculation helper                                                   |
| `ticketing.py`             | Ticket create/update/close/get operations                                       |
| `communications.py`        | Outbound email + chatops notifications                                          |
| `hitl.py`                  | HiTL request dispatch and callback-token persistence                            |
| `audit.py`                 | Audit event persistence                                                         |
| `evidence.py`              | Evidence bundle persistence                                                     |
| `provider_capabilities.py` | Generic connector execute/health bridge                                         |
| `_activity_errors.py`      | Shared retryability and error mapping helpers                                   |
| `_tenant_secrets.py`       | Tenant secret helper utility                                                    |

## Runtime Notes (Current Behavior)

- Activities are loaded by queue in `workers/run_worker.py`; queue alignment is mandatory for new activities.
- Polling dedup is durable and tracks processed provider events in DynamoDB.
- HiTL token writes use conditional expressions and reserved-word-safe attribute aliases.
- Outbound email uses tenant-first provider resolution with fallback to `ses` when `EMAIL_PROVIDER` is empty.

## Run and Verify

Run focused activity suites:

```bash
python -m pytest -q tests/test_activities
```

Run high-value cross-module regressions touched by recent changes:

```bash
python -m pytest -q tests/test_activities/test_hitl_token_workflow_target.py tests/test_polling_manager_helpers.py tests/test_connectors_resilience.py
```

## Change Checklist

1. Keep activity logic idempotent and retry-safe.
2. Use typed contracts from `shared.models` and provider contracts from `shared.providers`.
3. Register new activities in `workers/run_worker.py` under the correct queue.
4. Add or update tests in `tests/test_activities/` and related integration-safe suites.
5. Update this README when adding/removing activity modules.
