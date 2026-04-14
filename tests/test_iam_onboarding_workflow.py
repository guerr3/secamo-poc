from workflows.iam_onboarding import (
    LICENSE_APPROVE_ACTION,
    LICENSE_REJECT_ACTION,
    _build_license_approval_request,
)


def test_build_license_approval_request_uses_email_channel_and_expected_actions() -> None:
    request = _build_license_approval_request(
        tenant_id="tenant-001",
        workflow_id="wf-001",
        user_id="user-123",
        user_email="new.user@example.com",
        license_sku="SPE_E5",
        reviewer_email="noreply@secamo.local",
        timeout_hours=4,
    )

    assert request.workflow_id == "wf-001"
    assert request.tenant_id == "tenant-001"
    assert request.reviewer_email == "noreply@secamo.local"
    assert request.channels == ["email"]
    assert request.allowed_actions == [LICENSE_APPROVE_ACTION, LICENSE_REJECT_ACTION]
    assert request.metadata["user_id"] == "user-123"
    assert request.metadata["license_sku"] == "SPE_E5"
