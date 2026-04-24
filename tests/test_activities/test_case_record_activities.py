"""Unit tests for activities.case_record — CaseRecord persistence layer."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from activities.case_record import (
    _pk,
    _sk,
    create_case_record,
    get_case_record,
    update_case_status,
)


# ── Helpers ──────────────────────────────────────────────────────

def _dynamo_mock() -> MagicMock:
    return MagicMock()


# ── create_case_record ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_case_record_persists_strict_model():
    mock = _dynamo_mock()
    with (
        patch("activities.case_record._dynamo", mock),
        patch("activities.case_record.AUDIT_TABLE_NAME", "test-audit"),
    ):
        result = await create_case_record(
            "tenant-1", "case-abc", "wf-123", "risky_user", "high", "alert-xyz"
        )

    assert result == "case-abc"
    mock.put_item.assert_called_once()
    call_kwargs = mock.put_item.call_args.kwargs
    assert call_kwargs["TableName"] == "test-audit"
    item = call_kwargs["Item"]
    assert item["PK"] == {"S": "TENANT#tenant-1"}
    assert item["SK"] == {"S": "CASE#case-abc"}
    assert item["case_id"] == {"S": "case-abc"}
    assert item["tenant_id"] == {"S": "tenant-1"}
    assert item["workflow_id"] == {"S": "wf-123"}
    assert item["status"] == {"S": "open"}
    assert item["case_type"] == {"S": "risky_user"}
    assert item["severity"] == {"S": "high"}
    assert item["source_event_id"] == {"S": "alert-xyz"}
    assert "created_at" in item
    assert "updated_at" in item
    assert call_kwargs["ConditionExpression"] == "attribute_not_exists(SK)"


@pytest.mark.asyncio
async def test_create_case_record_idempotent_on_duplicate():
    mock = _dynamo_mock()
    error_response = {"Error": {"Code": "ConditionalCheckFailedException", "Message": "dup"}}
    mock.put_item.side_effect = ClientError(error_response, "PutItem")

    with (
        patch("activities.case_record._dynamo", mock),
        patch("activities.case_record.AUDIT_TABLE_NAME", "test-audit"),
    ):
        result = await create_case_record(
            "tenant-1", "case-abc", "wf-123", "risky_user", "high"
        )

    assert result == "case-abc"


@pytest.mark.asyncio
async def test_create_case_record_excludes_none_fields():
    mock = _dynamo_mock()
    with (
        patch("activities.case_record._dynamo", mock),
        patch("activities.case_record.AUDIT_TABLE_NAME", "test-audit"),
    ):
        await create_case_record(
            "tenant-1", "case-abc", "wf-123", "audit_log", "low"
        )

    item = mock.put_item.call_args.kwargs["Item"]
    # source_event_id is None so should not be in the item (exclude_none=True)
    assert "source_event_id" not in item


@pytest.mark.asyncio
async def test_create_case_record_fails_without_table_config():
    with (
        patch("activities.case_record.AUDIT_TABLE_NAME", ""),
    ):
        with pytest.raises(Exception, match="MissingAuditTableConfig"):
            await create_case_record(
                "tenant-1", "case-abc", "wf-123", "risky_user", "high"
            )


# ── update_case_status ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_update_case_status_sets_terminal_state():
    mock = _dynamo_mock()
    with (
        patch("activities.case_record._dynamo", mock),
        patch("activities.case_record.AUDIT_TABLE_NAME", "test-audit"),
    ):
        result = await update_case_status("tenant-1", "case-abc", "closed")

    assert result is True
    call_kwargs = mock.update_item.call_args.kwargs
    assert call_kwargs["Key"]["PK"] == {"S": "TENANT#tenant-1"}
    assert call_kwargs["Key"]["SK"] == {"S": "CASE#case-abc"}
    assert ":status" in call_kwargs["ExpressionAttributeValues"]
    assert call_kwargs["ExpressionAttributeValues"][":status"] == {"S": "closed"}
    # No ticket_id in the expression when not passed
    assert "#ticket_id" not in call_kwargs["ExpressionAttributeNames"]


@pytest.mark.asyncio
async def test_update_case_status_links_ticket_id():
    mock = _dynamo_mock()
    with (
        patch("activities.case_record._dynamo", mock),
        patch("activities.case_record.AUDIT_TABLE_NAME", "test-audit"),
    ):
        result = await update_case_status("tenant-1", "case-abc", "open", "TICKET-42")

    assert result is True
    call_kwargs = mock.update_item.call_args.kwargs
    assert "#ticket_id" in call_kwargs["ExpressionAttributeNames"]
    assert call_kwargs["ExpressionAttributeValues"][":ticket_id"] == {"S": "TICKET-42"}


# ── get_case_record ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_case_record_returns_item():
    mock = _dynamo_mock()
    mock.get_item.return_value = {
        "Item": {
            "PK": {"S": "TENANT#tenant-1"},
            "SK": {"S": "CASE#case-abc"},
            "case_id": {"S": "case-abc"},
            "status": {"S": "open"},
        }
    }
    with (
        patch("activities.case_record._dynamo", mock),
        patch("activities.case_record.AUDIT_TABLE_NAME", "test-audit"),
    ):
        result = await get_case_record("tenant-1", "case-abc")

    assert result is not None
    assert result["case_id"] == "case-abc"
    assert result["status"] == "open"


@pytest.mark.asyncio
async def test_get_case_record_returns_none_when_missing():
    mock = _dynamo_mock()
    mock.get_item.return_value = {}
    with (
        patch("activities.case_record._dynamo", mock),
        patch("activities.case_record.AUDIT_TABLE_NAME", "test-audit"),
    ):
        result = await get_case_record("tenant-1", "nonexistent")

    assert result is None


# ── Key format tests ─────────────────────────────────────────────

def test_pk_format():
    assert _pk("tenant-abc") == "TENANT#tenant-abc"


def test_sk_format():
    assert _sk("case-xyz") == "CASE#case-xyz"
