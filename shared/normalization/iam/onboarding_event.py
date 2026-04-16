from __future__ import annotations

from temporalio.exceptions import ApplicationError

from shared.models import UserLifecycleCaseInput
from shared.models.canonical import Envelope, IamOnboardingEvent


_ALLOWED_ACTIONS = {"create", "update", "delete", "password_reset"}


def _extract_user_id(payload: IamOnboardingEvent) -> str:
    user_data = payload.user_data
    candidates = [
        user_data.get("user_id"),
        user_data.get("id"),
        user_data.get("employee_id"),
        user_data.get("email"),
        payload.user_email,
    ]

    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()

    raise ApplicationError(
        "IamOnboardingEvent payload must include a user identifier",
        type="InvalidIamOnboardingPayload",
        non_retryable=True,
    )


def normalize_iam_onboarding_case(event: Envelope) -> UserLifecycleCaseInput:
    """Normalize iam.onboarding envelopes into UserLifecycleCaseInput for WF-01."""

    if not isinstance(event.payload, IamOnboardingEvent):
        raise ApplicationError(
            "normalize_iam_onboarding_case requires iam.onboarding payload",
            type="InvalidIamOnboardingPayload",
            non_retryable=True,
        )

    payload = event.payload
    action = payload.action.value if hasattr(payload.action, "value") else str(payload.action)
    action = action.strip().lower()

    if action not in _ALLOWED_ACTIONS:
        raise ApplicationError(
            f"Unsupported iam.onboarding action '{action}'",
            type="UnsupportedIamOnboardingAction",
            non_retryable=True,
        )

    return UserLifecycleCaseInput(
        tenant_id=event.tenant_id,
        action=action,
        user_id=_extract_user_id(payload),
        user_email=payload.user_email,
        requester=str(event.metadata.get("requester") or "ingress-api"),
    )
