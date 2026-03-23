# Connectors

> This folder provides the provider adapter contract and registry that activities use to execute provider-specific actions through a common interface.

## Files

| File | Purpose | Used By |
|------|---------|---------|
| `__init__.py` | Exports connector contract and registry helpers. | Activities and external imports. |
| `base.py` | Defines abstract `BaseConnector` contract (`fetch_events`, `execute_action`, `health_check`). | All concrete provider connectors. |
| `jira.py` | Jira Cloud connector implementation for ticket fetch/create/update/close/get and health checks. | `activities/ticketing.py`, `activities/connector_dispatch.py`. |
| `microsoft_defender.py` | Microsoft Graph/Defender connector for polling resources, enrichment, and isolate actions. | `activities/connector_dispatch.py`, alert enrichment flows. |
| `registry.py` | Maps provider keys to connector factories and resolves connector instances. | `activities/connector_dispatch.py`. |
| `stub_providers.py` | `[STUB]` Placeholder connectors for `crowdstrike`, `sentinelone`, `halo_itsm`, `servicenow`, `virustotal`, `abuseipdb`, and `misp`. | Registry fallback entries and future provider implementation slots. |
| `README.md` | Folder-level connector behavior and extension notes. | Engineers extending provider support. |

## How It Fits

Activities call connector operations through `get_connector(...)` from this folder instead of directly calling provider APIs, which keeps workflows provider-agnostic and deterministic in [../workflows/README.md](../workflows/README.md). Tenant secrets are resolved upstream in activity/bootstrap code from [../shared/README.md](../shared/README.md), then injected into connector instances. Worker runtime queue wiring that exposes these activities is defined in [../workers/README.md](../workers/README.md).

## Notes / Extension Points

- New providers must implement `BaseConnector`, then be added to `_CONNECTOR_FACTORIES` in `registry.py`.
- Connectors must either return a successful payload or raise a typed connector exception. Avoid returning `{"success": false}` for real failures.
- Use typed connector errors to express retry intent: permanent configuration/validation failures should be raised as non-retryable categories, while transient HTTP/network failures should be raised as retryable categories.
- Stub connectors intentionally return non-success placeholder results and should be replaced before claiming provider support.
- Keep connector methods idempotent and explicit because they are called through Temporal activity retries.
