from __future__ import annotations

from pathlib import Path


def test_iam_workflow_does_not_bootstrap_polling_managers() -> None:
    source = Path("workflows/iam_onboarding.py").read_text(encoding="utf-8")

    assert "PollingManagerWorkflow" not in source
    assert "config.polling_providers" not in source


def test_iam_workflow_password_generation_runs_via_activity() -> None:
    source = Path("workflows/iam_onboarding.py").read_text(encoding="utf-8")

    assert "identity_generate_temp_password" in source
    assert "secrets.choice" not in source


def test_disable_user_paths_do_not_call_identity_delete_user() -> None:
    incident_source = Path("workflows/child/incident_response.py").read_text(encoding="utf-8")
    deprovision_source = Path("workflows/child/user_deprovisioning.py").read_text(encoding="utf-8")

    assert "identity_delete_user" not in incident_source
    assert "identity_delete_user" not in deprovision_source
