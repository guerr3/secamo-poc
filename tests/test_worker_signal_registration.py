from __future__ import annotations

import ast
from pathlib import Path


RUN_WORKER_PATH = Path("workers/run_worker.py")


def _load_workflows_function() -> ast.FunctionDef:
    module = ast.parse(RUN_WORKER_PATH.read_text(encoding="utf-8"))
    for node in module.body:
        if isinstance(node, ast.FunctionDef) and node.name == "load_workflows":
            return node
    raise AssertionError("load_workflows() not found in workers/run_worker.py")


def _collect_edr_workflow_names(function_node: ast.FunctionDef) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(function_node):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        if not isinstance(node.func.value, ast.Name) or node.func.value.id != "edr_workflows":
            continue

        if node.func.attr == "append" and node.args and isinstance(node.args[0], ast.Name):
            names.add(node.args[0].id)
            continue

        if node.func.attr == "extend" and node.args:
            arg = node.args[0]
            if isinstance(arg, (ast.List, ast.Tuple)):
                for element in arg.elts:
                    if isinstance(element, ast.Name):
                        names.add(element.id)
    return names


def _collect_imported_workflow_modules(function_node: ast.FunctionDef) -> dict[str, set[str]]:
    imported: dict[str, set[str]] = {}
    for node in ast.walk(function_node):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.setdefault(node.module, set()).update(alias.name for alias in node.names)
    return imported


def test_all_four_signal_workflows_registered_in_edr_worker() -> None:
    load_workflows_fn = _load_workflows_function()
    edr_names = _collect_edr_workflow_names(load_workflows_fn)

    assert "SigninAnomalyDetectionWorkflow" in edr_names
    assert "RiskyUserTriageWorkflow" in edr_names
    assert "DeviceComplianceRemediationWorkflow" in edr_names
    assert "AuditLogAnomalyWorkflow" in edr_names


def test_soc_alert_triage_workflow_still_registered() -> None:
    load_workflows_fn = _load_workflows_function()
    edr_names = _collect_edr_workflow_names(load_workflows_fn)

    assert "SocAlertTriageWorkflow" in edr_names


def test_worker_imports_all_four_new_workflow_modules() -> None:
    load_workflows_fn = _load_workflows_function()
    imports = _collect_imported_workflow_modules(load_workflows_fn)

    expected_modules = {
        "workflows.signin_anomaly_detection": "SigninAnomalyDetectionWorkflow",
        "workflows.risky_user_triage": "RiskyUserTriageWorkflow",
        "workflows.device_compliance_remediation": "DeviceComplianceRemediationWorkflow",
        "workflows.audit_log_anomaly": "AuditLogAnomalyWorkflow",
    }

    for module_name, class_name in expected_modules.items():
        assert module_name in imports
        assert class_name in imports[module_name]
