from __future__ import annotations

from workflows.child.hitl_approval import _rebind_hitl_request_for_child
from shared.models import HiTLRequest
import activities.hitl as hitl_module


class _DynamoPutSpy:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def put_item(self, **kwargs):
        self.calls.append(kwargs)
        return {}


def test_put_token_record_uses_child_workflow_id_not_parent(monkeypatch) -> None:
    monkeypatch.setenv("HITL_TOKEN_TABLE", "hitl-table")

    put_spy = _DynamoPutSpy()
    monkeypatch.setattr(hitl_module, "_dynamo", put_spy)

    parent_request = HiTLRequest(
        workflow_id="parent-wf-100",
        run_id="",
        tenant_id="tenant-123",
        title="Approval",
        description="Needs decision",
        allowed_actions=["dismiss", "isolate"],
        reviewer_email="analyst@example.com",
        channels=["email"],
        metadata={"ticket": "SEC-9"},
    )

    child_request = _rebind_hitl_request_for_child(
        parent_request,
        child_workflow_id="child-hitl-100",
        child_run_id="child-run-100",
    )

    hitl_module._put_token_record(child_request, "tok-xyz")

    assert len(put_spy.calls) == 1
    item = put_spy.calls[0]["Item"]
    assert item["workflow_id"]["S"] == "child-hitl-100"
    assert item["workflow_id"]["S"] != "parent-wf-100"
