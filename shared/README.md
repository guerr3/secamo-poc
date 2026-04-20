# Shared

This module is the cross-cutting contract and runtime boundary layer used by ingress, workflows, activities, workers, and tests.

## Contract Ownership

- `shared.models` owns domain and event contracts.
- `shared.providers` owns provider protocols/types and provider-capability boundaries.
- Routing, normalization, and ingress dispatch utilities are centralized here to prevent drift.

## Package Map

| Path                  | Responsibility                                                                     |
| --------------------- | ---------------------------------------------------------------------------------- |
| `approval/`           | HiTL approval contracts and token-store helpers                                    |
| `auth/`               | Auth contracts, validator registry, and secret resolution                          |
| `config.py`           | Temporal and queue runtime constants plus shared env defaults                      |
| `graph_client.py`     | Graph/Defender token acquisition and cache behavior                                |
| `ingress/`            | Shared ingress pipeline contracts and orchestration helpers                        |
| `models/`             | Canonical envelope and workflow/domain input models                                |
| `normalization/`      | Typed normalization from inbound envelopes to workflow inputs                      |
| `providers/`          | Provider contracts, factory wiring, and capability typing                          |
| `routing/`            | Route contracts, route registry, and default mappings                              |
| `ssm_client.py`       | Tenant-scoped SSM read/write helpers                                               |
| `temporal/`           | Dispatch and workflow-starter abstractions                                         |
| `workflow_helpers.py` | Shared workflow helper primitives (bootstrap, observability, child start wrappers) |

## Runtime Notes (Current Behavior)

- Signal routing uses explicit rule predicates for `defender.security_signal` variants (`signin_log`, `risky_user`, `noncompliant_device`, `audit_log`).
- `workflow_input_for_route` shapes route payloads into typed inputs for IAM and dedicated SOC signal workflows.
- Ingress fanout and polling dispatch share the same route registry semantics.
- Auth validation is registry-driven and centralized for ingress routes.

## Run and Verify

```bash
python -m pytest -q tests/test_models.py tests/test_graph_client.py tests/test_case_intake_routing.py tests/test_dispatcher_signal_normalization.py tests/test_graph_webhook_routing.py
```

## Change Checklist

1. Place new contract types in the correct ownership package (`models` vs `providers`).
2. Keep routing updates in `shared/routing/defaults.py` and verify with tests.
3. Keep workflow input shaping in `shared/temporal/dispatcher.py`.
4. Keep ingress auth behavior in shared auth validators/registry.
5. Update this README when shared package responsibilities or boundaries change.
