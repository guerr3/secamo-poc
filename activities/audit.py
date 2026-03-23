from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import boto3
from temporalio import activity

from shared.config import AUDIT_TABLE_NAME


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
    activity.logger.info(f"[{tenant_id}] create_audit_log workflow={workflow_id}")
    if not AUDIT_TABLE_NAME:
        activity.logger.error(f"[{tenant_id}] AUDIT_TABLE_NAME not configured")
        return False

    now = datetime.now(timezone.utc)
    ttl = int((now + timedelta(days=90)).timestamp())

    try:
        _dynamo.put_item(
            TableName=AUDIT_TABLE_NAME,
            Item={
                "workflow_id": {"S": workflow_id},
                "timestamp": {"S": now.isoformat()},
                "tenant_id": {"S": tenant_id},
                "event_type": {"S": action},
                "message": {"S": result},
                "metadata": {"S": json.dumps(evidence or {})},
                "ttl": {"N": str(ttl)},
            },
        )
        return True
    except Exception as exc:
        activity.logger.error(f"[{tenant_id}] create_audit_log failed: {type(exc).__name__}")
        return False
