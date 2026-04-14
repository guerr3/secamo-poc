# Connectors - provider adapter abstraction layer

> This module encapsulates provider-specific implementations behind a common adapter contract.

## Responsibilities

- Define and enforce a stable connector interface used by activities.
- Isolate provider SDK and HTTP behavior from workflow/activity orchestration code.
- Centralize provider registration and connector factory resolution.
- Preserve compatibility with stub connectors for planned integrations.

## File Reference

| File                    | Responsibility                                                                  |
| ----------------------- | ------------------------------------------------------------------------------- |
| `__init__.py`           | Public exports for connector interfaces and registry helpers.                   |
| `base.py`               | Abstract connector contract (`fetch_events`, `execute_action`, `health_check`). |
| `errors.py`             | Connector-specific exception types and error taxonomy.                          |
| `jira.py`               | Jira connector implementation.                                                  |
| `jira_provisioner.py`   | Jira provisioning helper implementation.                                        |
| `microsoft_defender.py` | Microsoft Defender/Graph connector implementation.                              |
| `ses.py`                | AWS SES connector for outbound email actions.                                   |
| `README.md`             | Module documentation.                                                           |
| `registry.py`           | Connector factory registry and provider key resolution.                         |
| `stub_providers.py`     | Stub connector implementations for planned providers.                           |
| `__pycache__/`          | Generated Python bytecode cache directory.                                      |

## Key Concepts

- Adapter pattern: activities use one connector interface while concrete classes encapsulate provider differences.
- Registry-driven resolution: provider key strings map to connector factories in one place (`registry.py`).
- Typed error boundaries: connector failures are translated into explicit connector error classes before activity-level retry policy handling.

## Usage

Activities resolve connectors by provider key and execute actions without provider-specific branching in workflow code.

```python
connector = get_connector(provider, tenant_id, secrets)
result = await connector.execute_action(action, payload)
```

## Testing

```bash
python -m pytest -q tests/test_stub_connectors.py tests/test_connectors_resilience.py tests/test_jira_provisioner.py
```

## Extension Points

1. Add a new connector class in `connectors/` that extends `BaseConnector`.
2. Implement required interface methods and provider-specific auth/data handling.
3. Register the new provider key in `connectors/registry.py`.
4. Add tests for success/failure behavior in `tests/`.
5. Update this file table for the added module.

## SES Notes

- Provider key: `ses` (registered in `connectors/registry.py`).
- Supported action: `send_email`.
- Runtime must have IAM permissions for `ses:SendEmail` (and optionally `ses:SendRawEmail`, `ses:GetSendQuota`).
- `SECAMO_SENDER_EMAIL` must be a verified identity/domain in SES for the target region.
