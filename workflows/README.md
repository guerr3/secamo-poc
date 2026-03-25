# Workflows

> This folder defines parent Temporal workflows that orchestrate IAM and SOC automation, subscription reconciliation, and polling loops.

## What This Does

### Files

| File                            | Purpose                                                                                                         | Used By                                                                    |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `__init__.py`                   | Package marker (no workflow exports in this file).                                                              | Python module loading.                                                     |
| `defender_alert_enrichment.py`  | WF-02 parent workflow for Defender alert enrichment, optional threat intel, ticket creation, notify, and audit. | Started by ingress route fan-out for `defender.alert` intents.             |
| `graph_subscription_manager.py` | Long-running subscription reconciler with signals and continue-as-new lifecycle.                                | Manual/scheduled Temporal starts.                                          |
| `iam_onboarding.py`             | WF-01 parent workflow for user lifecycle (`create`, `update`, `delete`, `password_reset`) and audit logging.    | IAM ingress and lifecycle event starts.                                    |
| `impossible_travel.py`          | WF-05 parent workflow for risky sign-in triage, ticketing, HITL, and incident response.                         | Started by ingress route fan-out for `defender.impossible_travel` intents. |
| `polling_manager.py`            | Long-running poller that fetches provider events and starts routed child workflows.                             | Started from onboarding flow for configured polling providers.             |
| `child/README.md`               | Child workflow layer documentation.                                                                             | Parent workflows and maintainers.                                          |

This layer is the deterministic orchestration center between ingress events and side-effecting activity calls. Parent workflows start child workflows in `workflows/child/` to keep SOC/IAM flows reusable and composable. Queue registration and worker lifecycle are configured in `workers/run_worker.py`.

## How To Run

Workflows run via workers:

```bash
python -m workers.run_worker
```

## How To Verify

Run workflow-related tests and integration-safe unit coverage:

```bash
python -m pytest -q
```

## Troubleshooting

- Use child workflows for new multi-step branches instead of inflating parent run methods.
- `iam_onboarding.py` currently includes a TODO path with a hardcoded temporary password; replace with secure generation before production use.
- Route additions must stay consistent with code-defined routes in `shared/routing/defaults.py` and normalization output in `shared/normalization/normalizers.py`.
