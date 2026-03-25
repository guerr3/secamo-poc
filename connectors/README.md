# Connectors

> This folder provides the provider adapter contract and registry that activities use to execute provider-specific actions through a common interface.

## What This Does

### Files

| File                    | Purpose                                                                                                                             | Used By                                                             |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `__init__.py`           | Exports connector contract and registry helpers.                                                                                    | Activities and external imports.                                    |
| `base.py`               | Defines abstract `BaseConnector` contract (`fetch_events`, `execute_action`, `health_check`).                                       | All concrete provider connectors.                                   |
| `jira.py`               | Jira Cloud connector implementation for ticket fetch/create/update/close/get and health checks.                                     | `activities/ticketing.py`, `activities/connector_dispatch.py`.      |
| `microsoft_defender.py` | Microsoft Graph/Defender connector for polling resources, enrichment, and isolate actions.                                          | `activities/connector_dispatch.py`, alert enrichment flows.         |
| `registry.py`           | Maps provider keys to connector factories and resolves connector instances.                                                         | `activities/connector_dispatch.py`.                                 |
| `stub_providers.py`     | `[STUB]` Placeholder connectors for `crowdstrike`, `sentinelone`, `halo_itsm`, `servicenow`, `virustotal`, `abuseipdb`, and `misp`. | Registry fallback entries and future provider implementation slots. |
| `README.md`             | Folder-level connector behavior and extension notes.                                                                                | Engineers extending provider support.                               |

Activities call connector operations through `get_connector(...)` from this folder instead of directly calling provider APIs, which keeps workflows provider-agnostic and deterministic. Tenant secrets are resolved upstream in activity/bootstrap code and injected into connector instances. Worker queue wiring is defined in `workers/run_worker.py`.

## How To Run

This module has no standalone runtime process. It is exercised through workers and activities:

```bash
python -m workers.run_worker
```

## How To Verify

Run connector-related tests:

```bash
python -m pytest -q tests/test_stub_connectors.py tests/test_connectors_resilience.py tests/test_jira_provisioner.py
```

## Troubleshooting

- New providers must implement `BaseConnector`, then be added to `_CONNECTOR_FACTORIES` in `registry.py`.
- Connectors must either return a successful payload or raise a typed connector exception. Avoid returning `{"success": false}` for real failures.
- Use typed connector errors to express retry intent: permanent configuration/validation failures should be raised as non-retryable categories, while transient HTTP/network failures should be raised as retryable categories.
- Stub connectors intentionally return non-success placeholder results and should be replaced before claiming provider support.
- Keep connector methods idempotent and explicit because they are called through Temporal activity retries.
