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
async def test_create_audit_log_persists_soc_case_fields(mocker):
    """SOC workflows pass alert_id, ticket_id, case_type in the evidence dict.

    Verify these are extracted by the AuditLogRecord model and written to DynamoDB.
    """
    mocker.patch("activities.audit.AUDIT_TABLE_NAME", "audit-table")
    put_item = mocker.patch("activities.audit._dynamo.put_item", return_value={})

    evidence = {"alert_id": "a1", "ticket_id": "T-123", "case_type": "defender_alert"}
    ok = await create_audit_log("t1", "wf-1", "case_intake", "completed", evidence)
    assert ok is True

    item = put_item.call_args.kwargs["Item"]
    assert item["alert_id"] == {"S": "a1"}
    assert item["ticket_id"] == {"S": "T-123"}
    assert item["case_type"] == {"S": "defender_alert"}
    # expires_at should be present as a Number
    assert "N" in item["expires_at"]


@pytest.mark.asyncio
async def test_create_audit_log_excludes_none_fields(mocker):
    """Non-SOC callers (polling, onboarding) pass evidence without case keys.

    Verify alert_id, ticket_id, case_type are excluded from the DynamoDB item
    via model_dump(exclude_none=True).
    """
    mocker.patch("activities.audit.AUDIT_TABLE_NAME", "audit-table")
    put_item = mocker.patch("activities.audit._dynamo.put_item", return_value={})

    evidence = {"provider": "ms", "iteration": 5}
    ok = await create_audit_log("t1", "wf-1", "polling_cycle", "ok", evidence)
    assert ok is True

    item = put_item.call_args.kwargs["Item"]
    assert "alert_id" not in item
    assert "ticket_id" not in item
    assert "case_type" not in item


@pytest.mark.asyncio
async def test_collect_evidence_bundle_happy(mocker):
    mocker.patch("activities.evidence.EVIDENCE_BUCKET_NAME", "evidence-bucket")
    put_obj = mocker.patch("activities.evidence._s3.put_object", return_value={})
    bundle = await collect_evidence_bundle("t1", "wf-1", "a1", [{"x": 1}])
    assert bundle.bundle_url.startswith("s3://evidence-bucket/")
    assert put_obj.called
