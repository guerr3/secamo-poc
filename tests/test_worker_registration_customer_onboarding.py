from __future__ import annotations

from workers import run_worker


def test_customer_onboarding_workflow_is_registered_on_iam_queue() -> None:
    workflows_map = run_worker.load_workflows()
    workflow_names = {workflow_cls.__name__ for workflow_cls in workflows_map["iam"]}

    assert "CustomerOnboardingWorkflow" in workflow_names


def test_customer_onboarding_activities_are_registered_on_iam_queue() -> None:
    activities_map = run_worker.load_activities_by_queue()
    activity_names = {activity_fn.__name__ for activity_fn in activities_map["iam"]}

    assert "provision_customer_secrets" in activity_names
    assert "register_customer_tenant" in activity_names
