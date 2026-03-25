from __future__ import annotations

from workflows.child.hitl_approval import _rebind_hitl_request_for_child
from shared.models import HiTLRequest


def test_rebind_hitl_request_for_child_overrides_parent_identity() -> None:
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

    rebound = _rebind_hitl_request_for_child(
        original,
        child_workflow_id="child-hitl-999",
        child_run_id="child-run-abc",
    )

    assert rebound.workflow_id == "child-hitl-999"
    assert rebound.run_id == "child-run-abc"
    assert rebound.tenant_id == original.tenant_id
    assert rebound.ticket_key == original.ticket_key
    assert rebound.metadata == original.metadata

    assert original.workflow_id == "parent-wf-123"
    assert original.run_id == ""
