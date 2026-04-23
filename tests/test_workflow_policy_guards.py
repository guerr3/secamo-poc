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


def test_signin_anomaly_workflow_executes_incident_response_for_approved_actions() -> None:
    source = Path("workflows/signin_anomaly_detection.py").read_text(encoding="utf-8")

    assert "IncidentResponseWorkflow.run" in source
    assert "IncidentResponseRequest(" in source
    assert "decision.approved" in source
    assert "signin-incident-response-v1" in source


def test_signin_anomaly_workflow_uses_inline_hitl() -> None:
    source = Path("workflows/signin_anomaly_detection.py").read_text(encoding="utf-8")

    assert "request_hitl_approval" in source
    assert "workflow.wait_condition" in source
    assert "HiTLApprovalWorkflow" not in source


def test_risky_user_workflow_uses_inline_hitl() -> None:
    source = Path("workflows/risky_user_triage.py").read_text(encoding="utf-8")

    assert "request_hitl_approval" in source
    assert "workflow.wait_condition" in source
    assert "HiTLApprovalWorkflow" not in source


def test_device_compliance_workflow_uses_inline_hitl() -> None:
    source = Path("workflows/device_compliance_remediation.py").read_text(encoding="utf-8")

    assert "request_hitl_approval" in source
    assert "workflow.wait_condition" in source
    assert "HiTLApprovalWorkflow" not in source


def test_audit_log_workflow_uses_inline_hitl() -> None:
    source = Path("workflows/audit_log_anomaly.py").read_text(encoding="utf-8")

    assert "request_hitl_approval" in source
    assert "workflow.wait_condition" in source
    assert "HiTLApprovalWorkflow" not in source


def test_soc_alert_workflow_uses_inline_hitl() -> None:
    source = Path("workflows/soc_alert_triage.py").read_text(encoding="utf-8")

    assert "request_hitl_approval" in source
    assert "workflow.wait_condition" in source
    assert "HiTLApprovalWorkflow" not in source


def test_iam_workflow_has_inline_license_approval_path() -> None:
    source = Path("workflows/iam_onboarding.py").read_text(encoding="utf-8")

    assert "wf01-inline-license-hitl-v1" in source
    assert "request_hitl_approval" in source
    assert "workflow.wait_condition" in source
    assert "HiTLApprovalWorkflow" not in source

