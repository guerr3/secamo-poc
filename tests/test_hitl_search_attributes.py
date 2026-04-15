from __future__ import annotations

from pathlib import Path


def test_hitl_workflow_upserts_search_attributes() -> None:
    source = Path("workflows/child/hitl_approval.py").read_text(encoding="utf-8")

    assert "hitl-search-attributes-v1" in source
    assert "HiTLStatus" in source
    assert "TenantId" in source
