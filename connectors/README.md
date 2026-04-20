# Connectors

This module contains provider adapters that implement the shared connector contract.
Activities call these adapters through the registry, so workflows remain provider-agnostic.

## What This Module Owns

- Provider-specific API translation for fetch/action/health operations.
- Connector error normalization into typed connector exceptions.
- Central provider-key to connector-factory registration.

## Connector Contract

All connectors extend `BaseConnector` and implement:

- `fetch_events(query)`
- `execute_action(action, payload)`
- `health_check()`

## File Map

| File                    | Responsibility                                         |
| ----------------------- | ------------------------------------------------------ |
| `base.py`               | Base connector contract                                |
| `registry.py`           | Provider-key registry and connector factory lookup     |
| `errors.py`             | Connector error taxonomy                               |
| `microsoft_defender.py` | Microsoft Defender and Graph-backed security connector |
| `jira.py`               | Jira ticketing connector                               |
| `jira_provisioner.py`   | Jira-specific provisioning/helper logic                |
| `ses.py`                | AWS SES outbound email connector                       |
| `virustotal.py`         | VirusTotal threat-intel connector                      |
| `abuseipdb.py`          | AbuseIPDB threat-intel connector                       |
| `stub_providers.py`     | Stub connectors for planned providers                  |

## Registered Providers

| Provider Key         | Implementation                    | Status |
| -------------------- | --------------------------------- | ------ |
| `microsoft_defender` | `MicrosoftGraphConnector`         | Active |
| `microsoft_graph`    | `MicrosoftGraphConnector` (alias) | Active |
| `jira`               | `JiraConnector`                   | Active |
| `ses`                | `SesConnector`                    | Active |
| `virustotal`         | `VirusTotalConnector`             | Active |
| `abuseipdb`          | `AbuseIpdbConnector`              | Active |
| `crowdstrike`        | `CrowdStrikeConnector`            | Stub   |
| `sentinelone`        | `SentinelOneConnector`            | Stub   |
| `halo_itsm`          | `HaloItsmConnector`               | Stub   |
| `servicenow`         | `ServiceNowConnector`             | Stub   |
| `misp`               | `MispConnector`                   | Stub   |

## Runtime Notes (Current Behavior)

- Defender/Graph connector contains compatibility fallbacks for alert retrieval and enrichment paths (including `alerts_v2` behavior and best-effort managed device enrichment).
- Email connector support includes `ses`; runtime email provider fallback behavior is resolved in activity layer.
- Registry lookups are case-insensitive and fail fast when provider keys are unknown.

## Run and Verify

```bash
python -m pytest -q tests/test_connectors_resilience.py tests/test_threat_intel_connectors.py tests/test_ses_connector.py tests/test_jira_provisioner.py tests/test_stub_connectors.py
```

## Change Checklist

1. Add a new connector class under `connectors/` extending `BaseConnector`.
2. Register provider key mapping in `connectors/registry.py`.
3. Keep provider-specific response translation inside connector code.
4. Add tests for success, fallback, and error behavior.
5. Update this README when provider keys or connector files change.
