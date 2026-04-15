"""Polling deduplication activities.

Durably marks provider events as processed using DynamoDB conditional writes.
This activity is intentionally fail-open: on storage errors it returns "new"
so polling can continue while surfacing observability metadata.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from typing import Any

import boto3
from botocore.exceptions import ClientError
from temporalio import activity

from shared.config import AUDIT_TABLE_NAME, PROCESSED_EVENTS_TABLE_NAME

_DEFAULT_TTL_DAYS = 90


class _LazyDynamoClient:
    def __init__(self) -> None:
        self._client = None

    def _get_client(self):
        if self._client is None:
            self._client = boto3.client("dynamodb", region_name="eu-west-1")
        return self._client

    def put_item(self, *args, **kwargs):
        return self._get_client().put_item(*args, **kwargs)


_dynamo = _LazyDynamoClient()


def _resolve_table_name() -> str:
    configured = os.environ.get("PROCESSED_EVENTS_TABLE_NAME", "").strip()
    if configured:
        return configured

    # Backward-compatible fallback so dedup works without infra changes.
    if PROCESSED_EVENTS_TABLE_NAME:
        return PROCESSED_EVENTS_TABLE_NAME

    legacy = os.environ.get("AUDIT_TABLE_NAME", "").strip()
    if legacy:
        return legacy

    return AUDIT_TABLE_NAME.strip()


def _resolve_ttl_days() -> int:
    raw = os.environ.get("PROCESSED_EVENTS_TTL_DAYS", str(_DEFAULT_TTL_DAYS)).strip()
    try:
        parsed = int(raw)
        return parsed if parsed > 0 else _DEFAULT_TTL_DAYS
    except ValueError:
        return _DEFAULT_TTL_DAYS


def _safe_component(value: str) -> str:
    # Keep key structure stable and avoid path-like separators in SK.
    return value.replace("#", "_").replace("/", "_").strip()


@activity.defn
async def polling_mark_event_processed(
    tenant_id: str,
    provider: str,
    resource_type: str,
    event_type: str,
    dedup_event_id: str,
    workflow_event_id: str,
    provider_event_id: str | None = None,
) -> dict[str, Any]:
    """Atomically mark an event as processed and return whether it is new.

    Returns:
        {
            "is_new": bool,
            "status": "new"|"duplicate"|"fail_open"|"disabled",
            "dedup_enabled": bool,
            "fail_open": bool,
            "table_name": str | None,
            "reason": str,
        }
    """

    table_name = _resolve_table_name()
    if not table_name:
        activity.logger.warning(
            "[%s] polling dedup disabled: no table configured",
            tenant_id,
        )
        return {
            "is_new": True,
            "status": "disabled",
            "dedup_enabled": False,
            "fail_open": True,
            "table_name": None,
            "reason": "table_not_configured",
        }

    ttl_days = _resolve_ttl_days()
    now = datetime.now(timezone.utc)
    ttl = int((now + timedelta(days=ttl_days)).timestamp())

    pk = f"TENANT#{_safe_component(tenant_id)}"
    sk = (
        "PROCESSED#"
        f"{_safe_component(provider)}#"
        f"{_safe_component(resource_type)}#"
        f"{_safe_component(event_type)}#"
        f"{_safe_component(dedup_event_id)}"
    )

    try:
        _dynamo.put_item(
            TableName=table_name,
            Item={
                "PK": {"S": pk},
                "SK": {"S": sk},
                "event_scope": {
                    "S": f"{provider}:{resource_type}:{event_type}",
                },
                "dedup_event_id": {"S": dedup_event_id},
                "provider_event_id": {"S": provider_event_id or ""},
                "workflow_event_id": {"S": workflow_event_id},
                "created_at": {"S": now.isoformat()},
                "ttl": {"N": str(ttl)},
            },
            ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
        )
        return {
            "is_new": True,
            "status": "new",
            "dedup_enabled": True,
            "fail_open": False,
            "table_name": table_name,
            "reason": "inserted",
        }
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ConditionalCheckFailedException":
            return {
                "is_new": False,
                "status": "duplicate",
                "dedup_enabled": True,
                "fail_open": False,
                "table_name": table_name,
                "reason": "already_processed",
            }

        activity.logger.warning(
            "[%s] polling dedup fail-open due to client error (%s)",
            tenant_id,
            code or "unknown",
        )
        return {
            "is_new": True,
            "status": "fail_open",
            "dedup_enabled": True,
            "fail_open": True,
            "table_name": table_name,
            "reason": f"client_error:{code or 'unknown'}",
        }
    except Exception as exc:
        activity.logger.warning(
            "[%s] polling dedup fail-open due to unexpected error: %s",
            tenant_id,
            type(exc).__name__,
        )
        return {
            "is_new": True,
            "status": "fail_open",
            "dedup_enabled": True,
            "fail_open": True,
            "table_name": table_name,
            "reason": f"unexpected_error:{type(exc).__name__}",
        }
