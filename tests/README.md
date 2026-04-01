# Tests - verification suites for contracts, ingress, activities, and connectors

> This module contains automated tests that validate integration boundaries and behavior without live external dependencies.

## Responsibilities

- Validate model contracts and mapping transformations.
- Verify ingress routing, signature handling, and callback handling paths.
- Validate activity behavior and connector dispatch semantics.
- Provide regression safety for workflow-adjacent helper logic.

## File Reference

| File                                  | Responsibility                                          |
| ------------------------------------- | ------------------------------------------------------- |
| `approval/`                           | Approval-related test suites.                           |
| `auth/`                               | Auth validation and resolver tests.                     |
| `conftest.py`                         | Shared pytest fixtures and configuration.               |
| `contracts/`                          | Guardrails for legacy contract-import and boundary rules. |
| `e2e/`                                | End-to-end oriented test scenarios.                     |
| `normalization/`                      | Normalization and canonical mapping tests.              |
| `README.md`                           | Module documentation.                                   |
| `routing/`                            | Routing and dispatch behavior tests.                    |
| `test_activities/`                    | Activity-focused test suites.                           |
| `test_connectors_resilience.py`       | Connector resilience and error-path tests.              |
| `test_graph_client.py`                | Graph client token/cache tests.                         |
| `test_graph_webhook_routing.py`       | Graph webhook route resolution tests.                   |
| `test_hitl_child_identity_rebind.py`  | HiTL child workflow identity and signal behavior tests. |
| `test_ingress_graph_notifications.py` | Graph notification ingress behavior tests.              |
| `test_ingress_hitl_respond.py`        | HiTL callback ingress endpoint behavior tests.          |
| `test_ingress_mappers.py`             | Ingress mapper normalization tests.                     |
| `test_jira_provisioner.py`            | Jira provisioner behavior tests.                        |
| `test_models.py`                      | Shared model mapping and validation tests.              |
| `test_stub_connectors.py`             | Stub connector behavior tests.                          |
| `__pycache__/`                        | Generated Python bytecode cache directory.              |

## Key Concepts

- Boundary-first testing: tests target contracts and boundary behavior where ingress, routing, activity, and connector concerns intersect.
- Isolation by mocking: AWS/provider/Temporal interactions are mocked to keep tests deterministic and CI-friendly.
- Coverage by module intent: folder- and file-level suites align with architecture layers and key extension points.

## Usage

Most suites run directly from repository root with pytest.

```bash
python -m pytest -q
```

## Testing

```bash
python -m pytest -q
python -m pytest -q tests/test_activities
```

## Extension Points

1. Add new tests near the impacted behavior area (for example `test_activities/`, `routing/`, or root test files).
2. Reuse fixtures from `conftest.py` for stable setup and teardown.
3. Mock external systems; do not call live AWS or provider APIs.
4. Add regression tests for bug fixes and edge-case branches.
5. Update this file reference when a new top-level test file or folder is introduced.
