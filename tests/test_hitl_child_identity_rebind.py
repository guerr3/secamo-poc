from __future__ import annotations

from shared.models import HiTLRequest


def test_hitl_request_model_copy_overrides_identity() -> None:
    """Verify HiTLRequest.model_copy preserves all fields while overriding workflow identity.

    This replaces the legacy _rebind_hitl_request_for_child test — inline HiTL
    workflows now use model_copy() directly instead of a child-workflow rebind helper.
    """
    original = HiTLRequest(
        workflow_id="parent-wf-123",
        run_id="",
        tenant_id="tenant-001",
        title="Approval",
        description="Review request",
        allowed_actions=["dismiss", "isolate"],
        reviewer_email="analyst@example.com",
        ticket_key="SEC-1",
        channels=["email"],
        timeout_hours=4,
        metadata={"source": "wf-parent"},
    )

    rebound = original.model_copy(
        update={
            "workflow_id": "child-hitl-999",
            "run_id": "child-run-abc",
        }
    )

    assert rebound.workflow_id == "child-hitl-999"
    assert rebound.run_id == "child-run-abc"
    assert rebound.tenant_id == original.tenant_id
    assert rebound.ticket_key == original.ticket_key
    assert rebound.metadata == original.metadata

    # Original is frozen and unchanged
    assert original.workflow_id == "parent-wf-123"
    assert original.run_id == ""
