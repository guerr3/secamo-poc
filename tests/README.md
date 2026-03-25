# Tests

> This folder contains unit tests for shared model mapping, ingress validation/routing, selected activity modules, and tenant/runtime helpers.

## What This Does

### Files

| File                                                 | Purpose                                                                                                    | Used By                 |
| ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ----------------------- |
| `test_graph_client.py`                               | Verifies Graph token cache behavior, refresh paths, and auth failure handling in `shared/graph_client.py`. | Local/CI `pytest` runs. |
| `test_ingress_graph_notifications.py`                | Verifies Graph notification challenge echo and per-item dispatch behavior in ingress handler route logic.  | Local/CI `pytest` runs. |
| `test_graph_webhook_routing.py`                      | Verifies webhook resource routing to workflow name + queue from mapper tables.                             | Local/CI `pytest` runs. |
| `test_ingress_mappers.py`                            | Verifies Terraform ingress lambda mapper normalization for multiple provider payload shapes.               | Local/CI `pytest` runs. |
| `test_ingress_hitl_respond.py`                       | Verifies signed HITL callback ingest and response behavior in ingress route handling.                      | Local/CI `pytest` runs. |
| `test_models.py`                                     | Verifies provider-event-to-canonical/security/command conversion pipeline and approval mapping behavior.   | Local/CI `pytest` runs. |
| `test_connectors_resilience.py`                      | Verifies connector error-path behavior and retry-safe resilience expectations.                             | Local/CI `pytest` runs. |
| `test_hitl_child_identity_rebind.py`                 | Verifies HiTL child workflow identity/signal handling across callback boundaries.                          | Local/CI `pytest` runs. |
| `test_activities/test_audit_activities.py`           | Tests audit log writes and evidence bundle persistence behavior with mocked AWS clients.                   | Local/CI `pytest` runs. |
| `test_activities/test_connector_dispatch.py`         | Tests connector dispatch activity behavior for fetch/execute/health/threat-intel fanout paths.             | Local/CI `pytest` runs. |
| `test_activities/test_graph_alerts_activities.py`    | Tests alert enrichment/device/isolation/risk/threat-intel activity behavior using mocked HTTP responses.   | Local/CI `pytest` runs. |
| `test_activities/test_graph_users_activities.py`     | Tests Graph user lifecycle activity operations and idempotent delete handling.                             | Local/CI `pytest` runs. |
| `test_activities/test_hitl_dispatch_activity.py`     | Tests HiTL dispatch activity behavior for approval issue and callback metadata shaping.                    | Local/CI `pytest` runs. |
| `test_activities/test_hitl_token_workflow_target.py` | Tests token-to-workflow target integrity checks for HiTL callback flows.                                   | Local/CI `pytest` runs. |
| `test_activities/test_notifications_activities.py`   | Tests Teams and email notification activity success/error paths.                                           | Local/CI `pytest` runs. |
| `test_activities/test_tenant_config.py`              | Tests tenant config loading defaults and parsing from SSM mock responses.                                  | Local/CI `pytest` runs. |
| `test_activities/test_ticketing_activities.py`       | Tests ticket create/update/close/get wrappers over connector actions.                                      | Local/CI `pytest` runs. |

These tests validate critical behavior in shared contracts, activity logic, and ingress mapping paths. Most suites isolate side effects via monkeypatching or fake clients, so they can run without live AWS, Graph, or Temporal dependencies. Test runner behavior is configured by `pytest.ini`.

## How To Run

Run all tests:

```bash
python -m pytest -q
```

Run activity-focused tests:

```bash
python -m pytest -q tests/test_activities
```

## How To Verify

A successful run should complete without failures and cover key flows such as ingress mapping, connector dispatch, and tenant/bootstrap behavior.

## Troubleshooting

- Workflow orchestration modules in [../workflows/README.md](../workflows/README.md) currently have limited direct unit-test coverage; adding deterministic workflow tests is a natural next expansion.
- Connector implementations in [../connectors/README.md](../connectors/README.md) have minimal dedicated tests compared to activity wrappers.
- Keep fake clients and monkeypatch fixtures explicit to preserve deterministic assertions under `asyncio_mode=auto`.
