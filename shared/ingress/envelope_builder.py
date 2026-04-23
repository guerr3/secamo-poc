from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from shared.models.canonical import (
    Correlation,
    Envelope,
    SecamoEventVariantAdapter,
    StoragePartition,
    VendorExtension,
    derive_event_id,
)


def _severity_to_id(severity: str | None) -> int:
    mapping = {
        "informational": 10,
        "low": 20,
        "medium": 40,
        "high": 60,
        "critical": 80,
    }
    return mapping.get(str(severity or "").strip().lower(), 40)


def _deterministic_payload_hash(
    *,
    tenant_id: str,
    event_type: str,
    provider: str,
    raw_body: dict,
) -> str:
    """Build a stable hash from the canonical payload when no provider ID is available."""
    seed = {
        "tenant_id": tenant_id,
        "event_type": event_type,
        "provider": provider,
        "body": raw_body,
    }
    canonical = json.dumps(seed, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _resolve_provider_event_id(
    *,
    normalized: dict,
    raw_body: dict,
    tenant_id: str,
    event_type: str,
    provider: str,
) -> str:
    """Deterministic extraction chain for provider_event_id.

    Order: normalized event_id → raw event_id → correlation_id →
    request_id → deterministic payload hash composite.
    """
    # 1. Normalized event id
    candidate = normalized.get("event_id")
    if isinstance(candidate, str) and candidate.strip():
        return candidate.strip()

    # 2. Raw event id
    candidate = raw_body.get("event_id")
    if isinstance(candidate, str) and candidate.strip():
        return candidate.strip()

    # 3. Correlation id / request id
    for key in ("correlation_id", "request_id"):
        candidate = normalized.get(key) or raw_body.get(key)
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()

    # 4. Deterministic payload hash (last resort)
    return _deterministic_payload_hash(
        tenant_id=tenant_id,
        event_type=event_type,
        provider=provider,
        raw_body=raw_body,
    )


def _parse_occurred_at(raw_body: dict) -> datetime:
    raw_value = raw_body.get("occurred_at") or raw_body.get("timestamp")
    if isinstance(raw_value, str):
        candidate = raw_value.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(candidate)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _build_storage_partition(*, tenant_id: str, event_type: str, provider_event_id: str) -> StoragePartition:
    event_key = event_type.replace(".", "#")
    return StoragePartition(
        ddb_pk=f"TENANT#{tenant_id}",
        ddb_sk=f"EVENT#{event_key}#{provider_event_id}",
        s3_bucket=f"secamo-events-{tenant_id}",
        s3_key_prefix=f"raw/{event_type}/{provider_event_id}",
    )


def build_envelope(
    *,
    raw_body: dict,
    normalized: dict,
    provider: str,
    tenant_id: str,
    event_type: str,
) -> Envelope:
    provider_event_id = _resolve_provider_event_id(
        normalized=normalized,
        raw_body=raw_body,
        tenant_id=tenant_id,
        event_type=event_type,
        provider=provider,
    )
    occurred_at = _parse_occurred_at(raw_body)
    correlation_id = str(normalized.get("correlation_id") or raw_body.get("correlation_id") or provider_event_id)
    request_id = str(raw_body.get("request_id") or correlation_id)
    event_key = str(event_type).strip().lower()

    payload_candidate: dict
    if event_key == "defender.alert":
        alert = normalized.get("alert") if isinstance(normalized.get("alert"), dict) else {}
        severity = str(alert.get("severity") or normalized.get("severity") or "medium").lower()
        payload_candidate = {
            "event_type": "defender.alert",
            "activity_id": 2004,
            "activity_name": "alert_detected",
            "alert_id": str(alert.get("alert_id") or provider_event_id),
            "title": str(alert.get("title") or "Security alert"),
            "description": str(alert.get("description") or ""),
            "severity_id": _severity_to_id(severity),
            "severity": severity,
            "status": str(alert.get("status") or "open"),
            "vendor_extensions": {
                "source_ip": VendorExtension(source="ingress", value=alert.get("source_ip")),
                "destination_ip": VendorExtension(source="ingress", value=alert.get("destination_ip")),
                "device_id": VendorExtension(source="ingress", value=alert.get("device_id")),
                "user_email": VendorExtension(source="ingress", value=alert.get("user_email")),
            },
        }
    elif event_key == "defender.impossible_travel":
        user = normalized.get("user") if isinstance(normalized.get("user"), dict) else {}
        network = normalized.get("network") if isinstance(normalized.get("network"), dict) else {}
        severity = str(normalized.get("severity") or "high").lower()
        payload_candidate = {
            "event_type": "defender.impossible_travel",
            "activity_id": 3002,
            "activity_name": "impossible_travel",
            "user_principal_name": str(user.get("user_principal_name") or "unknown@example.com"),
            "source_ip": str(network.get("source_ip") or "0.0.0.0"),
            "destination_ip": (str(network.get("destination_ip")) if network.get("destination_ip") else None),
            "severity_id": _severity_to_id(severity),
            "severity": severity,
        }
    elif event_key == "iam.onboarding":
        user = normalized.get("user") if isinstance(normalized.get("user"), dict) else {}
        action = str(user.get("action") or "create").lower()
        activity_map = {"create": 1, "update": 2, "delete": 3, "password_reset": 4}
        payload_candidate = {
            "event_type": "iam.onboarding",
            "activity_id": activity_map.get(action, 1),
            "activity_name": action,
            "user_email": str(user.get("user_principal_name") or "unknown@example.com"),
            "action": action,
            "user_data": user.get("user_data") if isinstance(user.get("user_data"), dict) else {},
        }
    elif event_key == "hitl.approval":
        payload_candidate = {
            "event_type": "hitl.approval",
            "activity_id": 9001,
            "activity_name": "hitl_response",
            "approval_id": str(raw_body.get("approval_id") or provider_event_id),
            "decision": str(raw_body.get("decision") or "approved"),
            "channel": str(raw_body.get("channel") or "web"),
            "responder": (str(raw_body.get("responder")) if raw_body.get("responder") else None),
            "reason": (str(raw_body.get("reason")) if raw_body.get("reason") else None),
        }
    else:
        raise ValueError(f"unsupported_event_type:{event_key}")

    payload = SecamoEventVariantAdapter.validate_python(payload_candidate)

    event_id = derive_event_id(
        tenant_id=tenant_id,
        event_type=payload.event_type,
        occurred_at=occurred_at,
        correlation_id=correlation_id,
        provider_event_id=provider_event_id,
    )
    correlation = Correlation(
        correlation_id=correlation_id,
        causation_id=correlation_id,
        request_id=request_id,
        trace_id=correlation_id,
        storage_partition=_build_storage_partition(
            tenant_id=tenant_id,
            event_type=payload.event_type,
            provider_event_id=provider_event_id,
        ),
    )

    return Envelope(
        event_id=event_id,
        tenant_id=tenant_id,
        source_provider=provider,
        event_name=payload.event_type,
        schema_version="1.0.0",
        event_version="1.0.0",
        ocsf_version="1.1.0",
        occurred_at=occurred_at,
        correlation=correlation,
        payload=payload,
        metadata={
            "provider_event_id": provider_event_id,
            "requester": normalized.get("requester"),
            "ticket_id": normalized.get("ticket_id"),
        },
    )
