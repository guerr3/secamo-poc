# Tests

Automated verification for routing, normalization, workflows, activities, connectors, ingress handlers, and Terraform guardrails.

## Suite Map

| Path               | Focus                                                          |
| ------------------ | -------------------------------------------------------------- |
| `test_activities/` | Activity behavior, retries, and provider capability boundaries |
| `approval/`        | HiTL callback and token-store behavior                         |
| `auth/`            | Auth validator and resolver behavior                           |
| `contracts/`       | Contract ownership and import guardrails                       |
| `normalization/`   | Envelope-to-case normalization behavior                        |
| `routing/`         | Route registry and route resolution behavior                   |
| `e2e/`             | End-to-end-oriented scenarios (mocked boundaries)              |

Selected root suites:

- `test_case_intake_routing.py`
- `test_dispatcher_signal_normalization.py`
- `test_signal_workflow_structure.py`
- `test_worker_signal_registration.py`
- `test_polling_manager_helpers.py`
- `test_ingress_terraform_graph_validation_route.py`
- `test_connectors_resilience.py`
- `test_iam_onboarding_normalization.py`

## Test Principles

- Keep tests deterministic and offline (mock AWS/provider/Temporal boundaries).
- Add regression tests for every bug fix in routing, normalization, workflow wiring, and connector behavior.
- Keep structural guardrail tests in place for route/worker parity and workflow registration assumptions.

## Run and Verify

Run all tests:

```bash
python -m pytest -q
```

Run focused high-signal suites for recent changes:

```bash
python -m pytest -q tests/test_dispatcher_signal_normalization.py tests/test_signal_workflow_structure.py tests/test_worker_signal_registration.py tests/test_polling_manager_helpers.py tests/test_ingress_terraform_graph_validation_route.py tests/test_activities/test_hitl_token_workflow_target.py
```

## Change Checklist

1. Add tests in the closest behavioral area (activities/routing/normalization/workflow/ingress).
2. Keep fixtures centralized in `conftest.py`.
3. Avoid live cloud/provider calls.
4. Cover both success path and policy/guardrail failures.
5. Update this README when new top-level suites or test folders are added.
