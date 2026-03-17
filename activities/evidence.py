from __future__ import annotations

import json
from datetime import datetime, timezone

import boto3
from temporalio import activity

from shared.config import EVIDENCE_BUCKET_NAME
from shared.models import EvidenceBundle

_s3 = boto3.client("s3", region_name="eu-west-1")


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
