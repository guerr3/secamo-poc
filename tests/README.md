# Tests

> This folder contains unit tests for shared model mapping, Graph ingress validation/routing, selected activity modules, and tenant/runtime helpers.

## Files

| File | Purpose | Used By |
|------|---------|---------|
| `test_graph_client.py` | Verifies Graph token cache behavior, refresh paths, and auth failure handling in `shared/graph_client.py`. | Local/CI `pytest` runs. |
| `test_graph_ingress_validator.py` | Verifies tenant resolution from `clientState` and optional DynamoDB subscription metadata lookup in ingress validator. | Local/CI `pytest` runs. |
| `test_graph_webhook_routing.py` | Verifies webhook resource routing to workflow name + queue from mapper tables. | Local/CI `pytest` runs. |
| `test_ingress_mappers.py` | Verifies Terraform ingress lambda mapper normalization for multiple provider payload shapes. | Local/CI `pytest` runs. |
| `test_models.py` | Verifies provider-event-to-canonical/security/command conversion pipeline and approval mapping behavior. | Local/CI `pytest` runs. |
| `test_activities/test_audit_activities.py` | Tests audit log writes and evidence bundle persistence behavior with mocked AWS clients. | Local/CI `pytest` runs. |
| `test_activities/test_graph_alerts_activities.py` | Tests alert enrichment/device/isolation/risk/threat-intel activity behavior using mocked HTTP responses. | Local/CI `pytest` runs. |
| `test_activities/test_graph_users_activities.py` | Tests Graph user lifecycle activity operations and idempotent delete handling. | Local/CI `pytest` runs. |
| `test_activities/test_notifications_activities.py` | Tests Teams and email notification activity success/error paths. | Local/CI `pytest` runs. |
| `test_activities/test_tenant_config.py` | Tests tenant config loading defaults and parsing from SSM mock responses. | Local/CI `pytest` runs. |
| `test_activities/test_ticketing_activities.py` | Tests ticket create/update/close/get wrappers over connector actions. | Local/CI `pytest` runs. |

## How It Fits

These tests validate critical behavior in [../shared/README.md](../shared/README.md), [../activities/README.md](../activities/README.md), and ingress mapping logic consumed by [../graph_ingress/README.md](../graph_ingress/README.md). Most tests isolate side effects via monkeypatching or fake clients, so they run without live AWS, Graph, or Temporal dependencies. The test runner behavior is configured by `../pytest.ini`.

## Notes / Extension Points

- Workflow orchestration modules in [../workflows/README.md](../workflows/README.md) currently have limited direct unit-test coverage; adding deterministic workflow tests is a natural next expansion.
- Connector implementations in [../connectors/README.md](../connectors/README.md) have minimal dedicated tests compared to activity wrappers.
- Keep fake clients and monkeypatch fixtures explicit to preserve deterministic assertions under `asyncio_mode=auto`.
