from __future__ import annotations

from shared.models import SecurityCaseInput
from shared.models.canonical import DefenderDetectionFindingEvent, Envelope


def normalize_defender_alert_case(envelope: Envelope, *, auto_remediate: bool) -> SecurityCaseInput:
    """Normalize a defender.alert envelope into unified SecurityCaseInput."""

    if not isinstance(envelope.payload, DefenderDetectionFindingEvent):
        raise ValueError("normalize_defender_alert_case requires defender.alert payload")

    payload = envelope.payload
    severity = str(payload.severity or "medium").strip().lower() or "medium"
    if severity not in {"low", "medium", "high", "critical"}:
        severity = "medium"

    user_email = None
    user_extension = payload.vendor_extensions.get("user_email")
    if user_extension is not None and isinstance(user_extension.value, str):
        user_email = user_extension.value

    device_id = None
    device_extension = payload.vendor_extensions.get("device_id")
    if device_extension is not None and isinstance(device_extension.value, str):
        device_id = device_extension.value

    return SecurityCaseInput(
        tenant_id=envelope.tenant_id,
        case_type="defender_alert",
        severity=severity,
        alert_id=payload.alert_id,
        allowed_actions=["dismiss", "isolate", "disable_user"],
        auto_remediate=auto_remediate,
        identity=user_email,
        device=device_id,
        source_event=envelope,
    )
