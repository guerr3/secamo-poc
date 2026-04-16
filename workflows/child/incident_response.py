from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from activities.edr import edr_isolate_device
    from activities.evidence import collect_evidence_bundle
    from activities.identity import identity_revoke_sessions, identity_update_user
    from activities.ticketing import ticket_update
    from shared.models import EvidenceBundle, IncidentResponseRequest

RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)


@workflow.defn
class IncidentResponseWorkflow:
    """Reusable child workflow for post-approval SOC response actions.

    HiTLApprovalWorkflow may also trigger device isolation on timeout; this is
    intentional policy separation between approval timeout handling and explicit
    analyst-driven incident response actions.
    """

    @workflow.run
    async def run(self, request: IncidentResponseRequest) -> str:
        workflow.logger.info(
            "IncidentResponseWorkflow started - tenant=%s action=%s",
            request.tenant_id,
            request.decision.action,
        )

        action_result = ""

        if request.decision.action == "dismiss":
            await workflow.execute_activity(
                ticket_update,
                args=[
                    request.tenant_id,
                    request.ticketing_provider,
                    request.ticket_id,
                    {
                        "status": "closed",
                        "resolution": "false_positive",
                        "note": (
                            f"Dismissed by {request.decision.reviewer}: "
                            f"{request.decision.comments}"
                        ),
                    },
                ],
                start_to_close_timeout=TIMEOUT,
                retry_policy=RETRY_POLICY,
            )
            action_result = "Alert dismissed as false positive."

        elif request.decision.action == "isolate":
            if workflow.patched("incident-response-require-device-id-v1"):
                if not request.device_id:
                    raise ValueError("IncidentResponse isolate action requires device_id")
                resolved_device_id = request.device_id
            else:
                resolved_device_id = request.device_id or "unknown-device"
            await workflow.execute_activity(
                edr_isolate_device,
                args=[
                    request.tenant_id,
                    resolved_device_id,
                ],
                start_to_close_timeout=TIMEOUT,
                retry_policy=RETRY_POLICY,
            )
            await workflow.execute_activity(
                ticket_update,
                args=[
                    request.tenant_id,
                    request.ticketing_provider,
                    request.ticket_id,
                    {
                        "status": "in_progress",
                        "note": (
                            f"Device {resolved_device_id} isolated by "
                            f"{request.decision.reviewer}."
                        ),
                    },
                ],
                start_to_close_timeout=TIMEOUT,
                retry_policy=RETRY_POLICY,
            )
            action_result = f"Device '{resolved_device_id}' isolated."

        elif request.decision.action == "disable_user":
            if request.user:
                await workflow.execute_activity(
                    identity_revoke_sessions,
                    args=[request.tenant_id, request.user.user_id],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=RETRY_POLICY,
                )
                await workflow.execute_activity(
                    identity_update_user,
                    args=[request.tenant_id, request.user.user_id, {"accountEnabled": False}],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=RETRY_POLICY,
                )
                ticket_note = (
                    f"User {request.user_email} disabled by "
                    f"{request.decision.reviewer}."
                )
                action_result = f"User '{request.user_email}' disabled."
            else:
                ticket_note = (
                    f"User object for {request.user_email} was not resolved. "
                    "Skipped session revoke and account disable operations."
                )
                action_result = (
                    f"User '{request.user_email}' was not disabled because no identity user object was resolved."
                )

            await workflow.execute_activity(
                ticket_update,
                args=[
                    request.tenant_id,
                    request.ticketing_provider,
                    request.ticket_id,
                    {
                        "status": "in_progress",
                        "note": ticket_note,
                    },
                ],
                start_to_close_timeout=TIMEOUT,
                retry_policy=RETRY_POLICY,
            )

        evidence_url = "disabled-by-config"
        if request.evidence_bundle_enabled:
            evidence: EvidenceBundle = await workflow.execute_activity(
                collect_evidence_bundle,
                args=[
                    request.tenant_id,
                    request.parent_workflow_id,
                    request.alert_id,
                    [
                        {
                            "type": "threat_intel",
                            "data": {
                                "indicator": request.threat_intel.indicator,
                                "is_malicious": request.threat_intel.is_malicious,
                                "reputation_score": request.threat_intel.reputation_score,
                            },
                        },
                        {"type": "recent_alerts", "count": request.recent_alert_count},
                        {
                            "type": "decision",
                            "data": {
                                "action": request.decision.action,
                                "reviewer": request.decision.reviewer,
                                "comments": request.decision.comments,
                            },
                        },
                    ],
                ],
                start_to_close_timeout=TIMEOUT,
                retry_policy=RETRY_POLICY,
            )
            evidence_url = evidence.bundle_url

        return f"{action_result} Ticket: {request.ticket_id}, Evidence: {evidence_url}"
