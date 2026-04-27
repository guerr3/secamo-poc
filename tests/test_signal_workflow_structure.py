from __future__ import annotations

import ast
from pathlib import Path


WORKFLOW_FILES = {
    "SigninAnomalyDetectionWorkflow": Path("workflows/signin_anomaly_detection.py"),
    "RiskyUserTriageWorkflow": Path("workflows/risky_user_triage.py"),
    "DeviceComplianceRemediationWorkflow": Path("workflows/device_compliance_remediation.py"),
    "AuditLogAnomalyWorkflow": Path("workflows/audit_log_anomaly.py"),
}

# Workflows with inline HiTL approval that must define an approve signal handler.
INLINE_HITL_WORKFLOW_FILES = {
    **WORKFLOW_FILES,
    "SocAlertTriageWorkflow": Path("workflows/soc_alert_triage.py"),
    "IamOnboardingWorkflow": Path("workflows/iam_onboarding.py"),
}


def _read_source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _annotation_name(annotation: ast.AST | None) -> str | None:
    if annotation is None:
        return None
    if isinstance(annotation, ast.Name):
        return annotation.id
    if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
        return annotation.value
    if isinstance(annotation, ast.Attribute):
        return annotation.attr
    return None


def _find_run_method(path: Path) -> ast.AsyncFunctionDef | ast.FunctionDef | None:
    module = ast.parse(_read_source(path))
    for node in module.body:
        if not isinstance(node, ast.ClassDef):
            continue
        for child in node.body:
            if isinstance(child, (ast.AsyncFunctionDef, ast.FunctionDef)) and child.name == "run":
                return child
    return None


def _find_class_method_names(path: Path) -> set[str]:
    """Return the set of method names on the first workflow class in the file."""
    module = ast.parse(_read_source(path))
    names: set[str] = set()
    for node in module.body:
        if not isinstance(node, ast.ClassDef):
            continue
        for child in node.body:
            if isinstance(child, (ast.AsyncFunctionDef, ast.FunctionDef)):
                names.add(child.name)
        break
    return names


def test_all_four_workflows_define_run_method_with_security_case_input() -> None:
    for workflow_name, path in WORKFLOW_FILES.items():
        run_method = _find_run_method(path)
        assert run_method is not None, f"{workflow_name} is missing run() method"

        non_self_args = [arg for arg in run_method.args.args if arg.arg != "self"]
        assert non_self_args, f"{workflow_name}.run() must declare a case input argument"
        assert _annotation_name(non_self_args[0].annotation) == "SecurityCaseInput"


def test_all_four_workflows_call_emit_workflow_observability() -> None:
    for path in WORKFLOW_FILES.values():
        source = _read_source(path)
        assert "emit_workflow_observability" in source


def test_all_four_workflows_call_bootstrap_tenant() -> None:
    for path in WORKFLOW_FILES.values():
        source = _read_source(path)
        assert "bootstrap_tenant" in source


def test_all_four_workflows_call_create_soc_ticket() -> None:
    for path in WORKFLOW_FILES.values():
        source = _read_source(path)
        assert "create_soc_ticket" in source or "TicketCreationWorkflow" in source


def test_all_four_workflows_call_upsert_search_attributes() -> None:
    for path in WORKFLOW_FILES.values():
        source = _read_source(path)
        assert "upsert_search_attributes" in source


def test_risky_user_workflow_has_close_ticket_call() -> None:
    source = _read_source(WORKFLOW_FILES["RiskyUserTriageWorkflow"])

    assert source.count("create_soc_ticket") > 1 or "ticket_update" in source


def test_device_compliance_workflow_calls_isolate_device_or_antivirus() -> None:
    source = _read_source(WORKFLOW_FILES["DeviceComplianceRemediationWorkflow"])

    assert "isolate_device" in source
    assert "run_antivirus_scan" in source


def test_no_normalize_call_inside_workflow_files() -> None:
    forbidden_normalizers = [
        "normalize_signin_log_case",
        "normalize_risky_user_case",
        "normalize_noncompliant_device_case",
        "normalize_audit_log_case",
    ]

    for path in WORKFLOW_FILES.values():
        source = _read_source(path)
        for forbidden in forbidden_normalizers:
            assert forbidden not in source


def test_all_inline_hitl_workflows_define_approve_signal_handler() -> None:
    """Every workflow with inline HiTL must have an 'approve' method to receive decisions."""
    for workflow_name, path in INLINE_HITL_WORKFLOW_FILES.items():
        method_names = _find_class_method_names(path)
        assert "approve" in method_names, (
            f"{workflow_name} must define an 'approve' signal handler for inline HiTL"
        )


def test_soc_alert_triage_workflow_defines_run_method() -> None:
    path = INLINE_HITL_WORKFLOW_FILES["SocAlertTriageWorkflow"]
    run_method = _find_run_method(path)
    assert run_method is not None, "SocAlertTriageWorkflow is missing run() method"

    non_self_args = [arg for arg in run_method.args.args if arg.arg != "self"]
    assert non_self_args, "SocAlertTriageWorkflow.run() must declare an input argument"
    assert _annotation_name(non_self_args[0].annotation) == "SecurityCaseInput"
