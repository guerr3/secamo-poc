import json
from datetime import datetime, timezone
from temporalio import activity
from shared.models import EvidenceBundle


@activity.defn
async def create_audit_log(
    workflow_id: str,
    tenant_id: str,
    action: str,
    result: str,
    evidence: dict,
) -> bool:
    """
    Schrijft een audit event.
    Later: opslaan in DynamoDB tabel 'audit_events' (uit design doc).
    """
    activity.logger.info(
        f"[{tenant_id}] Audit log aanmaken voor workflow '{workflow_id}'"
    )

    log_entry = {
        "workflow_id": workflow_id,
        "tenant_id": tenant_id,
        "action": action,
        "result": result,
        "evidence": evidence,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # TODO: replace with real DynamoDB call
    activity.logger.info(f"AUDIT: {json.dumps(log_entry)}")
    return True


@activity.defn
async def collect_evidence_bundle(
    workflow_id: str,
    tenant_id: str,
    alert_id: str,
    items: list[dict],
) -> EvidenceBundle:
    """
    Verzamelt bewijs (logs, screenshots, configs) in een bundle voor compliance.
    Later: upload naar S3 en geef signed URL terug.
    """
    activity.logger.info(
        f"[{tenant_id}] Evidence bundle verzamelen voor alert '{alert_id}'"
    )

    # TODO: replace with real S3 upload
    bundle = EvidenceBundle(
        workflow_id=workflow_id,
        tenant_id=tenant_id,
        alert_id=alert_id,
        items=items,
        bundle_url=f"https://s3.eu-west-1.amazonaws.com/secamo-evidence/{workflow_id}/{alert_id}.zip",
    )
    activity.logger.info(f"Evidence bundle URL: {bundle.bundle_url}")
    return bundle
