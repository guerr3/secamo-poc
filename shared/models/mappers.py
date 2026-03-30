"""shared.models.mappers — Envelope-first conversion helpers.

RawIngressEnvelope/IAM requests are converted directly to canonical Envelope.
Workflow commands are generated directly from Envelope payload variants.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from shared.models.canonical import (
    Correlation,
    DefenderDetectionFindingEvent,
    Envelope,
    HitlApprovalEvent,
    IamOnboardingEvent,
    ImpossibleTravelEvent,
    SecamoEventVariantAdapter,
    StoragePartition,
    VendorExtension,
    derive_event_id,
)
from shared.models.commands import SignalWorkflowCommand, StartWorkflowCommand, WorkflowCommand
from shared.models.common import LifecycleAction
from shared.models.domain import ApprovalDecision
from shared.models.ingress import IamIngressRequest, RawIngressEnvelope
from shared.models.provider_events import DefenderWebhook, ProviderEvent, TeamsApprovalCallback


PROVIDER_EVENT_ROUTING: dict[tuple[str, str], tuple[str, str]] = {
    ("microsoft_defender", "alert"): ("DefenderAlertEnrichmentWorkflow", "soc-defender"),
    ("microsoft_defender", "impossible_travel"): ("ImpossibleTravelWorkflow", "soc-defender"),
    ("crowdstrike", "detection_summary"): ("DefenderAlertEnrichmentWorkflow", "soc-defender"),
    ("crowdstrike", "impossible_travel"): ("ImpossibleTravelWorkflow", "soc-defender"),
    ("sentinelone", "alert"): ("DefenderAlertEnrichmentWorkflow", "soc-defender"),
    ("jira", "jira:issue_created"): ("IamOnboardingWorkflow", "iam-graph"),
    ("jira", "jira:issue_updated"): ("IamOnboardingWorkflow", "iam-graph"),
    ("iam-api", "iam.onboarding"): ("IamOnboardingWorkflow", "iam-graph"),
    # Backwards-compatible alias used by current webhook mapper/tests.
    ("defender", "alert"): ("DefenderAlertEnrichmentWorkflow", "soc-defender"),
}

POLLING_RESOURCE_EVENT_TYPES: dict[tuple[str, str], str] = {
    ("microsoft_defender", "defender_alerts"): "alert",
    ("microsoft_defender", "entra_signin_logs"): "impossible_travel",
}

WEBHOOK_RESOURCE_ROUTING: dict[tuple[str, str], tuple[str, str]] = {
    ("microsoft_graph", "security/alerts"): ("DefenderAlertEnrichmentWorkflow", "soc-defender"),
    ("microsoft_graph", "security/alerts_v2"): ("DefenderAlertEnrichmentWorkflow", "soc-defender"),
    ("microsoft_graph", "auditlogs/signins"): ("ImpossibleTravelWorkflow", "soc-defender"),
    ("microsoft_graph", "identityprotection/riskyusers"): ("ImpossibleTravelWorkflow", "soc-defender"),
}

_EVENT_TYPE_TO_PROVIDER_EVENT_TYPE: dict[str, str] = {
    "defender.alert": "alert",
    "defender.impossible_travel": "impossible_travel",
    "iam.onboarding": "iam.onboarding",
}


def resolve_provider_event_route(provider: str, event_type: str) -> tuple[str, str] | None:
    return PROVIDER_EVENT_ROUTING.get((provider.lower(), event_type.lower()))


def resolve_polling_route(provider: str, resource_type: str, payload: Any | None = None) -> tuple[str, str] | None:
    provider_key = provider.lower()
    resource_key = resource_type.lower()
    configured_event_type = POLLING_RESOURCE_EVENT_TYPES.get((provider_key, resource_key))
    if not configured_event_type:
        return None

    provider_event_type = configured_event_type
    if isinstance(payload, dict) and payload.get("provider_event_type"):
        provider_event_type = str(payload["provider_event_type"])
    elif hasattr(payload, "event_type"):
        provider_event_type = _EVENT_TYPE_TO_PROVIDER_EVENT_TYPE.get(
            str(getattr(payload, "event_type")),
            configured_event_type,
        )

    return resolve_provider_event_route(provider, provider_event_type)


def resolve_webhook_route(provider: str, resource_type: str, payload: dict[str, Any] | None = None) -> tuple[str, str] | None:
    provider_key = provider.lower().strip()
    resource_key = resource_type.lower().strip().lstrip("/")

    if resource_key.count("/") >= 2:
        resource_key = resource_key.rsplit("/", 1)[0]

    direct = WEBHOOK_RESOURCE_ROUTING.get((provider_key, resource_key))
    if direct is not None:
        return direct

    if payload and payload.get("provider_event_type"):
        return resolve_provider_event_route(provider, str(payload["provider_event_type"]))

    return None


_PROVIDER_MAP: dict[str, type[ProviderEvent]] = {
    "defender": DefenderWebhook,
    "teams": TeamsApprovalCallback,
}


def build_provider_event(envelope: RawIngressEnvelope) -> ProviderEvent:
    provider_cls = _PROVIDER_MAP.get(envelope.provider.lower())
    if provider_cls is None:
        raise ValueError(f"Unknown provider: {envelope.provider!r}")

    base_fields: dict[str, Any] = {
        "provider": envelope.provider,
        "event_name": f"{envelope.provider}.webhook",
        "tenant_id": envelope.tenant_id,
        "received_at": envelope.received_at,
        "raw_payload": envelope.raw_body if isinstance(envelope.raw_body, dict) else {},
    }

    payload = envelope.raw_body if isinstance(envelope.raw_body, dict) else {}
    return provider_cls.model_validate({**base_fields, **payload})


def _storage_partition(tenant_id: str, event_name: str, provider_event_id: str | None) -> StoragePartition:
    event_suffix = provider_event_id or "ingress"
    normalized_event = event_name.replace(".", "#")
    return StoragePartition(
        ddb_pk=f"TENANT#{tenant_id}",
        ddb_sk=f"EVENT#{normalized_event}#{event_suffix}",
        s3_bucket=f"secamo-events-{tenant_id}",
        s3_key_prefix=f"raw/{event_name}/{event_suffix}",
    )


def _build_correlation(
    *,
    tenant_id: str,
    source_provider: str,
    request_id: str,
    event_name: str,
    provider_event_id: str | None,
) -> Correlation:
    corr_id = provider_event_id or request_id
    return Correlation(
        correlation_id=corr_id,
        causation_id=request_id,
        request_id=request_id,
        trace_id=request_id,
        storage_partition=_storage_partition(tenant_id, event_name, provider_event_id),
    )


def _defender_to_envelope(provider_event: DefenderWebhook, ingress: RawIngressEnvelope) -> Envelope:
    occurred_at = provider_event.occurred_at or ingress.received_at
    payload = DefenderDetectionFindingEvent(
        event_type="defender.alert",
        activity_id=2004,
        activity_name="ingress.webhook",
        alert_id=provider_event.alert_id,
        title=provider_event.title,
        description=provider_event.description,
        severity_id=40,
        severity=provider_event.severity,
        vendor_extensions={
            "source_ip": VendorExtension(source="defender", value=provider_event.source_ip),
            "destination_ip": VendorExtension(source="defender", value=provider_event.destination_ip),
            "device_id": VendorExtension(source="defender", value=provider_event.device_id),
            "user_email": VendorExtension(source="defender", value=provider_event.user_email),
        },
    )

    correlation = _build_correlation(
        tenant_id=ingress.tenant_id,
        source_provider=ingress.provider,
        request_id=ingress.request_id,
        event_name=payload.event_type,
        provider_event_id=provider_event.alert_id,
    )

    return Envelope(
        event_id=derive_event_id(
            tenant_id=ingress.tenant_id,
            event_type=payload.event_type,
            occurred_at=occurred_at,
            correlation_id=correlation.correlation_id,
            provider_event_id=provider_event.alert_id,
        ),
        tenant_id=ingress.tenant_id,
        source_provider=ingress.provider,
        event_name=payload.event_type,
        schema_version="1.0.0",
        event_version="1.0.0",
        ocsf_version="1.1.0",
        occurred_at=occurred_at,
        correlation=correlation,
        payload=payload,
        metadata={
            "request_id": ingress.request_id,
            "route": ingress.route,
            "method": ingress.method,
        },
    )


def _decision_from_callback(callback: TeamsApprovalCallback) -> str:
    if callback.approved:
        return "approved"
    return "rejected"


def _teams_to_envelope(provider_event: TeamsApprovalCallback, ingress: RawIngressEnvelope) -> Envelope:
    occurred_at = provider_event.occurred_at or ingress.received_at
    payload = HitlApprovalEvent(
        event_type="hitl.approval",
        activity_id=0,
        activity_name="ingress.callback",
        approval_id=provider_event.workflow_id,
        decision=_decision_from_callback(provider_event),
        channel="teams",
        responder=provider_event.reviewer,
        reason=provider_event.comments or None,
        vendor_extensions={
            "action": VendorExtension(source="teams", value=provider_event.action),
        },
    )

    correlation = _build_correlation(
        tenant_id=ingress.tenant_id,
        source_provider=ingress.provider,
        request_id=ingress.request_id,
        event_name=payload.event_type,
        provider_event_id=provider_event.workflow_id,
    )

    return Envelope(
        event_id=derive_event_id(
            tenant_id=ingress.tenant_id,
            event_type=payload.event_type,
            occurred_at=occurred_at,
            correlation_id=correlation.correlation_id,
            provider_event_id=provider_event.workflow_id,
        ),
        tenant_id=ingress.tenant_id,
        source_provider=ingress.provider,
        event_name=payload.event_type,
        schema_version="1.0.0",
        event_version="1.0.0",
        ocsf_version="1.1.0",
        occurred_at=occurred_at,
        correlation=correlation,
        payload=payload,
        metadata={
            "request_id": ingress.request_id,
            "route": ingress.route,
            "method": ingress.method,
        },
    )


def to_envelope(provider_event: ProviderEvent, ingress: RawIngressEnvelope) -> Envelope:
    if isinstance(provider_event, DefenderWebhook):
        return _defender_to_envelope(provider_event, ingress)
    if isinstance(provider_event, TeamsApprovalCallback):
        return _teams_to_envelope(provider_event, ingress)
    raise ValueError(f"No envelope mapping for {type(provider_event).__name__}")


def iam_request_to_envelope(
    request: IamIngressRequest,
    tenant_id: str,
    request_id: str | None = None,
) -> Envelope:
    now = datetime.now(timezone.utc)
    req_id = request_id or "internal-iam"
    user_email = str(request.user_data.get("email") or "")
    action = LifecycleAction(str(request.action))

    payload = IamOnboardingEvent(
        event_type="iam.onboarding",
        activity_id=3001,
        activity_name="iam.internal_request",
        user_email=user_email,
        action=action,
        user_data=request.user_data,
        vendor_extensions={
            "requester": VendorExtension(source="iam-api", value=request.requester),
            "ticket_id": VendorExtension(source="iam-api", value=request.ticket_id or ""),
        },
    )

    correlation = _build_correlation(
        tenant_id=tenant_id,
        source_provider="iam-api",
        request_id=req_id,
        event_name=payload.event_type,
        provider_event_id=request.ticket_id,
    )

    return Envelope(
        event_id=derive_event_id(
            tenant_id=tenant_id,
            event_type=payload.event_type,
            occurred_at=now,
            correlation_id=correlation.correlation_id,
            provider_event_id=request.ticket_id,
        ),
        tenant_id=tenant_id,
        source_provider="iam-api",
        event_name=payload.event_type,
        schema_version="1.0.0",
        event_version="1.0.0",
        ocsf_version="1.1.0",
        occurred_at=now,
        correlation=correlation,
        payload=payload,
        metadata={"request_id": req_id},
    )


def _envelope_to_start_route(envelope: Envelope) -> tuple[str, str]:
    payload = envelope.payload
    provider_event_type = _EVENT_TYPE_TO_PROVIDER_EVENT_TYPE.get(payload.event_type, payload.event_type)
    routed = resolve_provider_event_route(envelope.source_provider, provider_event_type)
    if routed is None:
        raise ValueError(
            f"No workflow mapping for provider={envelope.source_provider!r} event_type={payload.event_type!r}"
        )
    return routed


def to_workflow_command(envelope: Envelope) -> WorkflowCommand:
    if isinstance(envelope.payload, HitlApprovalEvent):
        return SignalWorkflowCommand(
            tenant_id=envelope.tenant_id,
            workflow_id=envelope.payload.approval_id,
            signal_name="approve",
            signal_payload={
                "approved": envelope.payload.decision == "approved",
                "reviewer": envelope.payload.responder or "unknown",
                "action": str(envelope.payload.vendor_extensions.get("action", VendorExtension(source="teams", value="dismiss")).value),
                "comments": envelope.payload.reason or "",
            },
        )

    workflow_name, task_queue = _envelope_to_start_route(envelope)
    return StartWorkflowCommand(
        tenant_id=envelope.tenant_id,
        workflow_name=workflow_name,
        task_queue=task_queue,
        workflow_input=envelope,
    )


def to_approval_decision(envelope: Envelope) -> ApprovalDecision:
    if not isinstance(envelope.payload, HitlApprovalEvent):
        raise ValueError("Approval decision conversion requires hitl.approval envelope payload")

    action_ext = envelope.payload.vendor_extensions.get("action")
    action = str(action_ext.value) if action_ext is not None else "dismiss"
    return ApprovalDecision(
        approved=envelope.payload.decision == "approved",
        reviewer=envelope.payload.responder or "unknown",
        action=action,
        comments=envelope.payload.reason or "",
    )


__all__ = [
    "build_provider_event",
    "iam_request_to_envelope",
    "resolve_polling_route",
    "resolve_provider_event_route",
    "resolve_webhook_route",
    "to_approval_decision",
    "to_envelope",
    "to_workflow_command",
]
