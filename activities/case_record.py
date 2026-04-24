from __future__ import annotations

import json
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError
from temporalio import activity

from activities._activity_errors import raise_activity_error
from shared.config import AUDIT_TABLE_NAME
from shared.models import CaseRecord


class _LazyDynamoClient:
    def __init__(self) -> None:
        self._client = None

    def _get_client(self):
        if self._client is None:
            self._client = boto3.client("dynamodb", region_name="eu-west-1")
        return self._client

    def put_item(self, **kwargs):
        return self._get_client().put_item(**kwargs)

    def update_item(self, **kwargs):
        return self._get_client().update_item(**kwargs)

    def get_item(self, **kwargs):
        return self._get_client().get_item(**kwargs)


_dynamo = _LazyDynamoClient()


def _pk(tenant_id: str) -> str:
    return f"TENANT#{tenant_id}"


def _sk(case_id: str) -> str:
    return f"CASE#{case_id}"


@activity.defn
async def create_case_record(
    tenant_id: str,
    case_id: str,
    workflow_id: str,
    case_type: str,
    severity: str,
    source_event_id: str | None = None,
) -> str:
    """Create a new CaseRecord in DynamoDB. Returns the case_id.

    Idempotent: if a record with the same PK+SK already exists the activity
    returns the case_id without failing, making it safe during Temporal replay.
    """
    activity.logger.info(
        "[%s] create_case_record case_id=%s workflow_id=%s",
        tenant_id, case_id, workflow_id,
    )
    if not AUDIT_TABLE_NAME:
        raise_activity_error(
            f"[{tenant_id}] AUDIT_TABLE_NAME not configured",
            error_type="MissingAuditTableConfig",
            non_retryable=True,
        )

    now = datetime.now(timezone.utc).isoformat()

    record = CaseRecord(
        case_id=case_id,
        tenant_id=tenant_id,
        workflow_id=workflow_id,
        status="open",
        created_at=now,
        updated_at=now,
        source_event_id=source_event_id,
        case_type=case_type,
        severity=severity,
    )

    item_data = record.model_dump(exclude_none=True)
    ddb_item = {
        "PK": {"S": _pk(tenant_id)},
        "SK": {"S": _sk(case_id)},
    }
    for k, v in item_data.items():
        ddb_item[k] = {"S": str(v)}

    try:
        _dynamo.put_item(
            TableName=AUDIT_TABLE_NAME,
            Item=ddb_item,
            ConditionExpression="attribute_not_exists(SK)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            activity.logger.info(
                "[%s] case_record already exists case_id=%s (idempotent)",
                tenant_id, case_id,
            )
            return case_id
        raise_activity_error(
            f"[{tenant_id}] create_case_record failed: {type(exc).__name__}",
            error_type="CaseRecordWriteFailed",
            non_retryable=False,
        )
    except Exception as exc:
        raise_activity_error(
            f"[{tenant_id}] create_case_record failed: {type(exc).__name__}",
            error_type="CaseRecordWriteFailed",
            non_retryable=False,
        )

    return case_id


@activity.defn
async def update_case_status(
    tenant_id: str,
    case_id: str,
    status: str,
    ticket_id: str | None = None,
) -> bool:
    """Update case status and optional ticket linkage."""
    activity.logger.info(
        "[%s] update_case_status case_id=%s status=%s",
        tenant_id, case_id, status,
    )
    if not AUDIT_TABLE_NAME:
        raise_activity_error(
            f"[{tenant_id}] AUDIT_TABLE_NAME not configured",
            error_type="MissingAuditTableConfig",
            non_retryable=True,
        )

    now = datetime.now(timezone.utc).isoformat()

    update_expr = "SET #status = :status, #updated_at = :updated_at"
    expr_names = {"#status": "status", "#updated_at": "updated_at"}
    expr_values = {
        ":status": {"S": status},
        ":updated_at": {"S": now},
    }

    if ticket_id is not None:
        update_expr += ", #ticket_id = :ticket_id"
        expr_names["#ticket_id"] = "ticket_id"
        expr_values[":ticket_id"] = {"S": ticket_id}

    try:
        _dynamo.update_item(
            TableName=AUDIT_TABLE_NAME,
            Key={
                "PK": {"S": _pk(tenant_id)},
                "SK": {"S": _sk(case_id)},
            },
            UpdateExpression=update_expr,
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values,
        )
        return True
    except Exception as exc:
        raise_activity_error(
            f"[{tenant_id}] update_case_status failed: {type(exc).__name__}",
            error_type="CaseRecordUpdateFailed",
            non_retryable=False,
        )


@activity.defn
async def get_case_record(
    tenant_id: str,
    case_id: str,
) -> dict | None:
    """Read case record for query use-cases. Returns None if not found."""
    activity.logger.info(
        "[%s] get_case_record case_id=%s",
        tenant_id, case_id,
    )
    if not AUDIT_TABLE_NAME:
        raise_activity_error(
            f"[{tenant_id}] AUDIT_TABLE_NAME not configured",
            error_type="MissingAuditTableConfig",
            non_retryable=True,
        )

    try:
        response = _dynamo.get_item(
            TableName=AUDIT_TABLE_NAME,
            Key={
                "PK": {"S": _pk(tenant_id)},
                "SK": {"S": _sk(case_id)},
            },
        )
    except Exception as exc:
        raise_activity_error(
            f"[{tenant_id}] get_case_record failed: {type(exc).__name__}",
            error_type="CaseRecordReadFailed",
            non_retryable=False,
        )

    item = response.get("Item")
    if item is None:
        return None

    return {k: list(v.values())[0] for k, v in item.items()}
