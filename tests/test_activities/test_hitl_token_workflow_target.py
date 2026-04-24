from __future__ import annotations

from shared.models import HiTLRequest
import activities.hitl as hitl_module


class _DynamoPutSpy:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def put_item(self, **kwargs):
        self.calls.append(kwargs)
        return {}


def test_put_token_record_uses_workflow_id_from_request(monkeypatch) -> None:
    """Verify _put_token_record writes the correct workflow_id from the HiTLRequest.

    Inline HiTL workflows set workflow_id and run_id via model_copy() before
    dispatching the approval request — the token record must reflect those values.
    """
    monkeypatch.setenv("HITL_TOKEN_TABLE", "hitl-table")

    put_spy = _DynamoPutSpy()
    monkeypatch.setattr(hitl_module, "_dynamo", put_spy)

    request = HiTLRequest(
        workflow_id="inline-wf-100",
        run_id="inline-run-100",
        tenant_id="tenant-123",
        title="Approval",
        description="Needs decision",
        allowed_actions=["dismiss", "isolate"],
        reviewer_email="analyst@example.com",
        channels=["email"],
        metadata={"ticket": "SEC-9"},
    )

    hitl_module._put_token_record(request, "tok-xyz")

    assert len(put_spy.calls) == 1
    put_call = put_spy.calls[0]
    item = put_call["Item"]
    assert item["workflow_id"]["S"] == "inline-wf-100"
    assert put_call["ConditionExpression"] == "attribute_not_exists(#token)"
    assert put_call["ExpressionAttributeNames"] == {"#token": "token"}
