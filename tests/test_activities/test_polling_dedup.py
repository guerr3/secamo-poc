from __future__ import annotations

from botocore.exceptions import ClientError
import pytest

import activities.polling_dedup as dedup_module


class _FakeDynamo:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.calls: list[dict] = []

    def put_item(self, *args, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return {"ok": True}


@pytest.mark.asyncio
async def test_polling_mark_event_processed_inserts_new_record(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeDynamo()
    monkeypatch.setattr(dedup_module, "_dynamo", fake)
    monkeypatch.setenv("PROCESSED_EVENTS_TABLE_NAME", "processed-events")
    monkeypatch.delenv("AUDIT_TABLE_NAME", raising=False)

    result = await dedup_module.polling_mark_event_processed(
        "tenant-1",
        "microsoft_defender",
        "defender_alerts",
        "defender.alert",
        "alert-123",
        "wf-evt-1",
        "alert-123",
    )

    assert result["status"] == "new"
    assert result["is_new"] is True
    assert result["dedup_enabled"] is True
    assert len(fake.calls) == 1
    assert fake.calls[0]["TableName"] == "processed-events"


@pytest.mark.asyncio
async def test_polling_mark_event_processed_detects_duplicate(monkeypatch: pytest.MonkeyPatch) -> None:
    duplicate_error = ClientError(
        {
            "Error": {
                "Code": "ConditionalCheckFailedException",
                "Message": "duplicate",
            }
        },
        "PutItem",
    )
    fake = _FakeDynamo(error=duplicate_error)
    monkeypatch.setattr(dedup_module, "_dynamo", fake)
    monkeypatch.setenv("PROCESSED_EVENTS_TABLE_NAME", "processed-events")

    result = await dedup_module.polling_mark_event_processed(
        "tenant-1",
        "microsoft_defender",
        "defender_alerts",
        "defender.alert",
        "alert-123",
        "wf-evt-1",
        "alert-123",
    )

    assert result["status"] == "duplicate"
    assert result["is_new"] is False
    assert result["fail_open"] is False


@pytest.mark.asyncio
async def test_polling_mark_event_processed_fail_open_on_storage_error(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeDynamo(error=RuntimeError("dynamo unavailable"))
    monkeypatch.setattr(dedup_module, "_dynamo", fake)
    monkeypatch.setenv("PROCESSED_EVENTS_TABLE_NAME", "processed-events")

    result = await dedup_module.polling_mark_event_processed(
        "tenant-1",
        "microsoft_defender",
        "defender_alerts",
        "defender.alert",
        "alert-123",
        "wf-evt-1",
        "alert-123",
    )

    assert result["status"] == "fail_open"
    assert result["is_new"] is True
    assert result["fail_open"] is True


@pytest.mark.asyncio
async def test_polling_mark_event_processed_uses_audit_table_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeDynamo()
    monkeypatch.setattr(dedup_module, "_dynamo", fake)
    monkeypatch.delenv("PROCESSED_EVENTS_TABLE_NAME", raising=False)
    monkeypatch.setenv("AUDIT_TABLE_NAME", "audit-fallback")

    result = await dedup_module.polling_mark_event_processed(
        "tenant-1",
        "microsoft_defender",
        "defender_alerts",
        "defender.alert",
        "alert-123",
        "wf-evt-1",
        "alert-123",
    )

    assert result["status"] == "new"
    assert result["table_name"] == "audit-fallback"
