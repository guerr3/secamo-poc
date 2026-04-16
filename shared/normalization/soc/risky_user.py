from __future__ import annotations

from shared.models import SecurityCaseInput
from shared.models.canonical import DefenderSecuritySignalEvent, Envelope


def normalize_risky_user_case(envelope: Envelope, *, auto_remediate: bool) -> SecurityCaseInput:
    """Normalize a defender.security_signal(risky_user) envelope into SecurityCaseInput."""

    payload = envelope.payload
    if not isinstance(payload, DefenderSecuritySignalEvent) or payload.provider_event_type != "risky_user":
        raise ValueError(
            "normalize_risky_user_case requires defender.security_signal payload with provider_event_type=risky_user"
        )

    severity = str(payload.severity or "medium").strip().lower() or "medium"
    if severity not in {"low", "medium", "high", "critical"}:
        severity = "medium"

    identity = None
    user_email_extension = payload.vendor_extensions.get("user_email")
    if user_email_extension is not None and isinstance(user_email_extension.value, str):
        identity = user_email_extension.value
    if identity is None:
        upn_extension = payload.vendor_extensions.get("user_principal_name")
        if upn_extension is not None and isinstance(upn_extension.value, str):
            identity = upn_extension.value

    device = None
    device_extension = payload.vendor_extensions.get("device_id")
    if device_extension is not None and isinstance(device_extension.value, str):
        device = device_extension.value

    return SecurityCaseInput(
        tenant_id=envelope.tenant_id,
        case_type="risky_user",
        severity=severity,
        alert_id=payload.signal_id,
        allowed_actions=["dismiss", "isolate", "disable_user"],
        auto_remediate=auto_remediate,
        identity=identity,
        device=device,
        source_event=envelope,
    )
