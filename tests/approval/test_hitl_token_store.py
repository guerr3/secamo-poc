"""Phase-4 verification for HITL token TTL and retention semantics.

Responsibility: verify TTL environment handling and used/used_at update behavior without deletes.
This module must not test callback parsing logic or workflow signaling behavior.
"""

from __future__ import annotations

from shared.approval.token_store import (
    DEFAULT_HITL_TOKEN_TTL_SECONDS,
    HITL_TOKEN_TTL_ENV_VAR,
    DynamoDbHitlTokenStore,
    get_hitl_token_ttl_seconds,
)


class _SpyDynamoClient:
    def __init__(self) -> None:
        self.put_calls: list[dict] = []
        self.update_calls: list[dict] = []

    def put_item(self, **kwargs):
        self.put_calls.append(kwargs)
        return {}

    def update_item(self, **kwargs):
        self.update_calls.append(kwargs)
        return {"Attributes": {"token": {"S": kwargs["Key"]["token"]["S"]}, "used": {"BOOL": False}}}


def test_token_ttl_uses_default_when_missing_or_invalid() -> None:
    assert get_hitl_token_ttl_seconds({}) == DEFAULT_HITL_TOKEN_TTL_SECONDS
    assert get_hitl_token_ttl_seconds({HITL_TOKEN_TTL_ENV_VAR: "abc"}) == DEFAULT_HITL_TOKEN_TTL_SECONDS
    assert get_hitl_token_ttl_seconds({HITL_TOKEN_TTL_ENV_VAR: "0"}) == DEFAULT_HITL_TOKEN_TTL_SECONDS


def test_token_ttl_uses_env_override() -> None:
    assert get_hitl_token_ttl_seconds({HITL_TOKEN_TTL_ENV_VAR: "1200"}) == 1200


def test_create_token_applies_ttl_and_mark_used_sets_used_at_without_delete() -> None:
    spy = _SpyDynamoClient()
    store = DynamoDbHitlTokenStore(
        table_name="hitl-table",
        dynamo_client=spy,
        environment={HITL_TOKEN_TTL_ENV_VAR: "900"},
        time_provider=lambda: 1_000,
    )

    record = store.create_token(
        token="tok-1",
        workflow_id="wf-1",
        tenant_id="tenant-1",
        reviewer_identity="email:analyst@example.com",
        channel="email",
        allowed_actions=("approve", "dismiss"),
    )

    assert record.created_at == 1_000
    assert record.expires_at == 1_900
    assert len(spy.put_calls) == 1
    put_item = spy.put_calls[0]["Item"]
    assert put_item["used"] == {"BOOL": False}
    assert put_item["expires_at"] == {"N": "1900"}

    previous = store.mark_token_used("tok-1")
    assert previous is not None
    assert len(spy.update_calls) == 1
    update_call = spy.update_calls[0]
    assert "used_at" in update_call["UpdateExpression"]
    assert update_call["ExpressionAttributeValues"][":used_at"] == {"N": "1000"}
    assert update_call["ConditionExpression"].find("expires_at > :now_epoch") != -1
