from __future__ import annotations

from shared.models import SecurityCaseInput
from shared.models.canonical import Envelope, AuthenticationEvent


def normalize_impossible_travel_case(envelope: Envelope, *, auto_remediate: bool) -> SecurityCaseInput:
    """Normalize a defender.impossible_travel envelope into SecurityCaseInput."""

    if not isinstance(envelope.payload, AuthenticationEvent):
        raise ValueError("normalize_impossible_travel_case requires impossible_travel payload")

    payload = envelope.payload
    severity = str(payload.severity or "high").strip().lower() or "high"
    if severity not in {"low", "medium", "high", "critical"}:
        severity = "high"

    device_id = None
    device_extension = payload.vendor_extensions.get("device_id")
    if device_extension is not None and isinstance(device_extension.value, str):
        device_id = device_extension.value

    return SecurityCaseInput(
        tenant_id=envelope.tenant_id,
        case_type="impossible_travel",
        severity=severity,
        alert_id=envelope.event_id,
        allowed_actions=["dismiss", "isolate", "disable_user"],
        auto_remediate=auto_remediate,
        identity=payload.user_principal_name,
        device=device_id,
        source_event=envelope,
    )
