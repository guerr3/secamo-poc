from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import boto3
from temporalio import activity

from activities._activity_errors import raise_activity_error
from shared.config import AUDIT_TABLE_NAME
from shared.models.canonical import AuditLogRecord


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


@activity.defn
async def create_audit_log(
    tenant_id: str,
    workflow_id: str,
    action: str,
    result: str,
    evidence: dict,
) -> bool:
    """Persist a workflow audit record using ``AuditLogRecord`` strict model."""
    activity.logger.info(f"[{tenant_id}] create_audit_log workflow={workflow_id}")
    if not AUDIT_TABLE_NAME:
        raise_activity_error(
            f"[{tenant_id}] AUDIT_TABLE_NAME not configured",
            error_type="MissingAuditTableConfig",
            non_retryable=True,
        )

    now = datetime.now(timezone.utc)
    expires_at = int((now + timedelta(days=90)).timestamp())

    pk = f"TENANT#{tenant_id}"
    sk = f"AUDIT#{now.isoformat()}#{workflow_id}"

    # Extract optional case fields from evidence metadata.
    # Safe extraction: non-SOC callers (polling, onboarding) don't pass
    # these keys — None values are semantically correct and excluded
    # from DynamoDB GSI2 indexing.
    alert_id = evidence.get("alert_id") if isinstance(evidence, dict) else None
    ticket_id = evidence.get("ticket_id") if isinstance(evidence, dict) else None
    case_type = evidence.get("case_type") if isinstance(evidence, dict) else None

    record = AuditLogRecord(
        PK=pk,
        SK=sk,
        workflow_id=workflow_id,
        tenant_id=tenant_id,
        event_type=action,
        message=result,
        alert_id=str(alert_id) if alert_id else None,
        ticket_id=str(ticket_id) if ticket_id else None,
        case_type=str(case_type) if case_type else None,
        expires_at=expires_at,
    )

    try:
        # Dump model to DynamoDB-compatible item format
        item_data = record.model_dump(exclude_none=True)
        ddb_item = {
            k: {"S": str(v)} if isinstance(v, str) else {"N": str(v)}
            for k, v in item_data.items()
        }
        # Preserve original metadata JSON as supplementary field
        ddb_item["metadata"] = {"S": json.dumps(evidence or {})}

        _dynamo.put_item(TableName=AUDIT_TABLE_NAME, Item=ddb_item)
        return True
    except Exception as exc:
        raise_activity_error(
            f"[{tenant_id}] create_audit_log failed: {type(exc).__name__}",
            error_type="AuditWriteFailed",
            non_retryable=False,
        )
