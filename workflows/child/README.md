# Child Workflows

Reusable child workflows composed by SOC, IAM, and onboarding parent workflows.

## Child Workflow Inventory

| File                                         | Workflow Class                                 | Purpose                                          |
| -------------------------------------------- | ---------------------------------------------- | ------------------------------------------------ |
| `alert_enrichment.py`                        | `AlertEnrichmentWorkflow`                      | Alert enrichment stage for SOC pipelines         |
| `threat_intel_enrichment.py`                 | `ThreatIntelEnrichmentWorkflow`                | Threat-intel fanout and normalization stage      |
| `incident_response.py`                       | `IncidentResponseWorkflow`                     | Response/remediation branching stage             |
| `ticket_creation.py`                         | `TicketCreationWorkflow`                       | Ticket creation stage                            |
| `hitl_approval.py`                           | `HiTLApprovalWorkflow`                         | Human-in-the-loop approval and signal wait stage |
| `user_deprovisioning.py`                     | `UserDeprovisioningWorkflow`                   | User deprovisioning stage                        |
| `onboarding_bootstrap_stage.py`              | `OnboardingBootstrapStageWorkflow`             | Tenant bootstrap/config stage                    |
| `onboarding_subscription_reconcile_stage.py` | `OnboardingSubscriptionReconcileStageWorkflow` | Graph subscription reconciliation stage          |
| `onboarding_communications_stage.py`         | `OnboardingCommunicationsStageWorkflow`        | Onboarding communication and ticket stage        |
| `onboarding_compliance_evidence_stage.py`    | `OnboardingComplianceEvidenceStageWorkflow`    | Onboarding compliance evidence stage             |

## Runtime Notes (Current Behavior)

- Subscription reconcile stage is best-effort and non-blocking for failed create attempts.
- HiTL approval stage is queue-isolated on `interactions` and receives callback signals from ingress.
- Ticket creation stage executes on queue `ticketing` for provider isolation.

## Run and Verify

```bash
python -m pytest -q tests/test_hitl_child_identity_rebind.py tests/test_onboarding_subscription_reconcile_stage_policy.py tests/test_workflow_stage_registration.py
```

## Change Checklist

1. Keep child workflows focused on one stage responsibility.
2. Register child workflows in `workers/run_worker.py` where required.
3. Ensure parent workflow composition calls are updated for new/renamed child workflows.
4. Keep activity side effects out of workflow code except through `execute_activity`.
5. Add stage-specific tests for signals, retries, and branch behavior.
