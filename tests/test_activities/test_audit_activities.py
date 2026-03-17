from __future__ import annotations

import pytest

from activities.audit import create_audit_log
from activities.evidence import collect_evidence_bundle


@pytest.mark.asyncio
async def test_create_audit_log_happy(mocker):
    mocker.patch("activities.audit.AUDIT_TABLE_NAME", "audit-table")
    put_item = mocker.patch("activities.audit._dynamo.put_item", return_value={})
    ok = await create_audit_log("t1", "wf-1", "event", "message", {"k": "v"})
    assert ok is True
    assert put_item.called


@pytest.mark.asyncio
async def test_collect_evidence_bundle_happy(mocker):
    mocker.patch("activities.evidence.EVIDENCE_BUCKET_NAME", "evidence-bucket")
    put_obj = mocker.patch("activities.evidence._s3.put_object", return_value={})
    bundle = await collect_evidence_bundle("t1", "wf-1", "a1", [{"x": 1}])
    assert bundle.bundle_url.startswith("s3://evidence-bucket/")
    assert put_obj.called
