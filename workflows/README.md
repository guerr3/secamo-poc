# Workflows

> This folder defines parent Temporal workflows that orchestrate IAM and SOC automation, subscription reconciliation, and polling loops.

## Files

| File | Purpose | Used By |
|------|---------|---------|
| `__init__.py` | Package marker (no workflow exports in this file). | Python module loading. |
| `defender_alert_enrichment.py` | WF-02 parent workflow for Defender alert enrichment, optional threat intel, ticket creation, notify, and audit. | Started by ingress route fan-out for `defender.alert` intents. |
| `graph_subscription_manager.py` | Long-running subscription reconciler with signals and continue-as-new lifecycle. | Manual/scheduled Temporal starts. |
| `iam_onboarding.py` | WF-01 parent workflow for user lifecycle (`create`, `update`, `delete`, `password_reset`) and audit logging. | IAM ingress and lifecycle event starts. |
| `impossible_travel.py` | WF-05 parent workflow for risky sign-in triage, ticketing, HITL, and incident response. | Started by ingress route fan-out for `defender.impossible_travel` intents. |
| `polling_manager.py` | Long-running poller that fetches provider events and starts routed child workflows. | Started from onboarding flow for configured polling providers. |
| `child/README.md` | Child workflow layer documentation. | Parent workflows and maintainers. |

## How It Fits

This layer is the deterministic orchestration center between ingress events from [../graph_ingress/README.md](../graph_ingress/README.md) and side-effecting activity calls in [../activities/README.md](../activities/README.md). Parent workflows start child workflows in [child/README.md](child/README.md) to split larger SOC/IAM flows into reusable stages. Queue registration and worker lifecycle are configured in [../workers/README.md](../workers/README.md).

## Notes / Extension Points

- Use child workflows for new multi-step branches instead of inflating parent run methods.
- `iam_onboarding.py` currently includes a TODO path with a hardcoded temporary password; replace with secure generation before production use.
- Route additions must stay consistent with code-defined routes in `shared/routing/defaults.py` and normalization output in `shared/normalization/normalizers.py`.
