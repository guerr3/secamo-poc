from __future__ import annotations

from workers import run_worker


def test_onboarding_stage_workflows_are_registered() -> None:
    workflows_map = run_worker.load_workflows()

    user_lifecycle_names = {workflow_cls.__name__ for workflow_cls in workflows_map["user_lifecycle"]}
    edr_names = {workflow_cls.__name__ for workflow_cls in workflows_map["edr"]}

    assert "OnboardingBootstrapStageWorkflow" in user_lifecycle_names
    assert "OnboardingCommunicationsStageWorkflow" in user_lifecycle_names
    assert "OnboardingComplianceEvidenceStageWorkflow" in user_lifecycle_names
    assert "OnboardingSubscriptionReconcileStageWorkflow" in edr_names


def test_polling_operational_workflow_is_registered() -> None:
    workflows_map = run_worker.load_workflows()
    polling_names = {workflow_cls.__name__ for workflow_cls in workflows_map["polling"]}

    assert "PollingManagerWorkflow" in polling_names
    assert "PollingBootstrapWorkflow" in polling_names
