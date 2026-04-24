from __future__ import annotations

from pathlib import Path


def test_inline_hitl_search_attributes_in_signal_workflows() -> None:
    """Verify that all inline HiTL signal workflows upsert TenantId search attribute."""
    workflow_files = [
        "workflows/signin_anomaly_detection.py",
        "workflows/risky_user_triage.py",
        "workflows/audit_log_anomaly.py",
        "workflows/device_compliance_remediation.py",
    ]

    for wf_path in workflow_files:
        source = Path(wf_path).read_text(encoding="utf-8")
        assert "TenantId" in source, f"{wf_path} must upsert TenantId search attribute"
