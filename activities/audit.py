from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import boto3
from temporalio import activity

from shared.config import AUDIT_TABLE_NAME, EVIDENCE_BUCKET_NAME
from shared.models import EvidenceBundle

_s3 = boto3.client("s3", region_name="eu-west-1")
_dynamo = boto3.client("dynamodb", region_name="eu-west-1")


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


@activity.defn
async def collect_evidence_bundle(
    tenant_id: str,
    workflow_id: str,
    alert_id: str,
    items: list[dict],
) -> EvidenceBundle:
    activity.logger.info(f"[{tenant_id}] collect_evidence_bundle alert={alert_id}")
    if not EVIDENCE_BUCKET_NAME:
        activity.logger.error(f"[{tenant_id}] EVIDENCE_BUCKET_NAME not configured")
        return EvidenceBundle(
            workflow_id=workflow_id,
            tenant_id=tenant_id,
            alert_id=alert_id,
            items=items,
            bundle_url="",
        )

    key = f"evidence/{tenant_id}/{alert_id}/{workflow_id}.json"
    payload = {
        "workflow_id": workflow_id,
        "tenant_id": tenant_id,
        "alert_id": alert_id,
        "items": items,
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        _s3.put_object(
            Bucket=EVIDENCE_BUCKET_NAME,
            Key=key,
            Body=json.dumps(payload).encode("utf-8"),
            ContentType="application/json",
            ServerSideEncryption="aws:kms",
        )
        bundle_url = f"s3://{EVIDENCE_BUCKET_NAME}/{key}"
    except Exception as exc:
        activity.logger.error(f"[{tenant_id}] collect_evidence_bundle failed: {type(exc).__name__}")
        bundle_url = ""

    return EvidenceBundle(
        workflow_id=workflow_id,
        tenant_id=tenant_id,
        alert_id=alert_id,
        items=items,
        bundle_url=bundle_url,
    )
