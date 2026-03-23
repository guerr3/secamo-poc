from __future__ import annotations

from shared.models import GraphNotificationEnvelope

from graph_ingress.validator import GraphIngressValidator


class _FakeTable:
    def __init__(self, item: dict | None) -> None:
        self._item = item

    def get_item(self, Key: dict) -> dict:
        return {"Item": self._item} if self._item else {}


class _FakeDynamo:
    def __init__(self, item: dict | None) -> None:
        self._item = item

    def Table(self, name: str) -> _FakeTable:  # noqa: N802
        return _FakeTable(self._item)


def test_validator_resolves_via_subscription_lookup(monkeypatch) -> None:
    import graph_ingress.validator as validator_module

    monkeypatch.setattr(validator_module, "GRAPH_SUBSCRIPTIONS_TABLE", "secamo-graph-subscriptions")
    validator = GraphIngressValidator(validation_app_ids={"app-id"})
    validator._ddb = _FakeDynamo(
        {
            "subscription_id": "sub-1",
            "tenant_id": "tenant-demo-001",
            "client_state": "secamo:tenant-demo-001:security-alerts_v2",
        }
    )
    validator._validate_validation_tokens = lambda tokens: True

    payload = GraphNotificationEnvelope.model_validate(
        {
            "value": [
                {
                    "subscriptionId": "sub-1",
                    "changeType": "created",
                    "resource": "security/alerts_v2/1",
                    "clientState": "secamo:tenant-demo-001:security-alerts_v2",
                }
            ]
        }
    )

    resolved = validator.validate_and_resolve(payload)
    assert len(resolved) == 1
    assert resolved[0].tenant_id == "tenant-demo-001"


def test_validator_rejects_client_state_mismatch(monkeypatch) -> None:
    import graph_ingress.validator as validator_module

    monkeypatch.setattr(validator_module, "GRAPH_SUBSCRIPTIONS_TABLE", "secamo-graph-subscriptions")
    validator = GraphIngressValidator(validation_app_ids={"app-id"})
    validator._ddb = _FakeDynamo(
        {
            "subscription_id": "sub-2",
            "tenant_id": "tenant-demo-002",
            "client_state": "secamo:tenant-demo-002:security-alerts_v2",
        }
    )
    validator._validate_validation_tokens = lambda tokens: True

    payload = GraphNotificationEnvelope.model_validate(
        {
            "value": [
                {
                    "subscriptionId": "sub-2",
                    "changeType": "updated",
                    "resource": "security/alerts_v2/2",
                    "clientState": "tampered-state",
                }
            ]
        }
    )

    resolved = validator.validate_and_resolve(payload)
    assert resolved == []


def test_validator_rejects_unvalidated_rich_notifications(monkeypatch) -> None:
    import graph_ingress.validator as validator_module

    monkeypatch.setattr(validator_module, "GRAPH_SUBSCRIPTIONS_TABLE", "secamo-graph-subscriptions")
    validator = GraphIngressValidator(validation_app_ids=set())
    validator._ddb = _FakeDynamo(
        {
            "subscription_id": "sub-3",
            "tenant_id": "tenant-demo-003",
            "client_state": "secamo:tenant-demo-003:security-alerts_v2",
        }
    )

    payload = GraphNotificationEnvelope.model_validate(
        {
            "value": [
                {
                    "subscriptionId": "sub-3",
                    "changeType": "created",
                    "resource": "security/alerts_v2/3",
                    "clientState": "secamo:tenant-demo-003:security-alerts_v2",
                }
            ],
            "validationTokens": ["invalid-token"],
        }
    )

    resolved = validator.validate_and_resolve(payload)
    assert resolved == []
