"""Phase-1 architecture guardrails for ingress contract modules.

Responsibility: enforce non-functional constraints for Phase 1 contract-only modules.
This test module must not assert provider behavior, workflow behavior, or transport behavior.
"""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PHASE1_MODULES = [
    REPO_ROOT / "shared" / "ingress" / "__init__.py",
    REPO_ROOT / "shared" / "ingress" / "contracts.py",
    REPO_ROOT / "shared" / "ingress" / "pipeline.py",
    REPO_ROOT / "shared" / "ingress" / "errors.py",
]

DISALLOWED_TERMS = [
    "microsoft",
    "defender",
    "crowdstrike",
    "sentinelone",
    "jira",
    "slack",
    "teams",
]

DISALLOWED_IMPORT_SNIPPETS = [
    "import temporalio",
    "from temporalio",
    "import boto3",
    "from boto3",
]


def test_phase1_modules_have_required_docstring_constraints() -> None:
    for module in PHASE1_MODULES:
        content = module.read_text(encoding="utf-8")
        assert content.startswith('"""')
        lowered = content.lower()
        assert "responsibility:" in lowered
        assert "must not contain" in lowered


def test_phase1_modules_exclude_provider_terms() -> None:
    for module in PHASE1_MODULES:
        content_lower = module.read_text(encoding="utf-8").lower()
        for term in DISALLOWED_TERMS:
            assert term not in content_lower, f"Unexpected provider-specific term '{term}' in {module}"


def test_phase1_modules_exclude_sdk_imports() -> None:
    for module in PHASE1_MODULES:
        content_lower = module.read_text(encoding="utf-8").lower()
        for import_snippet in DISALLOWED_IMPORT_SNIPPETS:
            assert import_snippet not in content_lower, f"Unexpected sdk import '{import_snippet}' in {module}"
