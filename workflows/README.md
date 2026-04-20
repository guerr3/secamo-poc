# Workflows

This folder contains deterministic Temporal workflows for SOC, IAM, onboarding, and polling orchestration.

## Workflow Inventory

| File                               | Workflow Class                        | Purpose                                                             |
| ---------------------------------- | ------------------------------------- | ------------------------------------------------------------------- |
| `soc_alert_triage.py`              | `SocAlertTriageWorkflow`              | Main SOC triage path for alerts and fallback security signals       |
| `signin_anomaly_detection.py`      | `SigninAnomalyDetectionWorkflow`      | Dedicated signin-log signal handling                                |
| `risky_user_triage.py`             | `RiskyUserTriageWorkflow`             | Dedicated risky-user signal handling                                |
| `device_compliance_remediation.py` | `DeviceComplianceRemediationWorkflow` | Dedicated noncompliant-device signal handling                       |
| `audit_log_anomaly.py`             | `AuditLogAnomalyWorkflow`             | Dedicated audit-log signal handling                                 |
| `iam_onboarding.py`                | `IamOnboardingWorkflow`               | IAM lifecycle orchestration with HiTL-gated license assignment path |
| `customer_onboarding.py`           | `CustomerOnboardingWorkflow`          | Parent onboarding workflow composed from stage child workflows      |
| `polling_bootstrap.py`             | `PollingBootstrapWorkflow`            | Polling manager bootstrap/reconciliation                            |
| `polling_manager.py`               | `PollingManagerWorkflow`              | Poll events, dedup, route, and continue-as-new loop                 |

## Routing and Queue Alignment

- Ingress and polling routing are defined in `shared/routing/defaults.py`.
- Worker registration is defined in `workers/run_worker.py`.
- Route and worker parity is validated at startup via `_validate_route_worker_parity`.

Primary queue mapping:

- `user-lifecycle`: IAM + customer onboarding + onboarding child stages
- `edr`: SOC parent + dedicated SOC signal workflows + selected child stages
- `polling`: polling bootstrap and polling manager

## Runtime Notes (Recent Changes)

- Dedicated SOC signal workflows are active for `signin_log`, `risky_user`, `noncompliant_device`, and `audit_log`.
- Polling manager now resolves routes from full envelopes and reuses shared route input shaping.
- Polling manager supports optional Graph subscription renewal when poll type includes `graph_subscription_renewal`.

## Run and Verify

```bash
python -m workers.run_worker
```

```bash
python -m pytest -q tests/test_worker_signal_registration.py tests/test_signal_workflow_structure.py tests/test_polling_manager_helpers.py tests/test_workflow_stage_registration.py
```

## Change Checklist

1. Keep workflow code deterministic and side-effect free.
2. Register new workflows in `workers/run_worker.py` on the correct queue.
3. Add route mappings in `shared/routing/defaults.py` when ingress/polling-triggered.
4. Keep workflow input shaping aligned in `shared/temporal/dispatcher.py`.
5. Add tests for routing, worker registration, and workflow structure guardrails.
