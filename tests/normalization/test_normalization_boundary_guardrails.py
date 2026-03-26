"""Phase-3 guardrails for normalization contract boundaries.

Responsibility: enforce that internal canonical wrappers remain private and legacy WorkflowIntent surfaces are removed.
This module must not test runtime provider parsing behavior.
"""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
NON_NORMALIZATION_MODULES = [
    REPO_ROOT / "shared" / "ingress" / "contracts.py",
    REPO_ROOT / "shared" / "ingress" / "pipeline.py",
    REPO_ROOT / "shared" / "temporal" / "signal_gateway.py",
    REPO_ROOT / "shared" / "auth" / "registry.py",
]


def test_internal_canonical_module_declares_private_intent() -> None:
    content = (REPO_ROOT / "shared" / "normalization" / "internal_canonical.py").read_text(encoding="utf-8").lower()
    assert "must not be consumed as a public contract" in content


def test_non_normalization_modules_do_not_import_internal_canonical() -> None:
    for module in NON_NORMALIZATION_MODULES:
        content = module.read_text(encoding="utf-8")
        assert "internal_canonical" not in content, f"Unexpected internal canonical import in {module}"


def test_public_normalization_surface_exports_no_legacy_intent_contract() -> None:
    content = (REPO_ROOT / "shared" / "normalization" / "__init__.py").read_text(encoding="utf-8")
    assert "WorkflowIntent" not in content
    assert "InternalCanonicalEvent" not in content
