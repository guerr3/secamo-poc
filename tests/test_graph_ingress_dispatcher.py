from __future__ import annotations

from types import SimpleNamespace

import pytest

from graph_ingress.dispatcher import TemporalGraphIngressDispatcher


class _FakeFanout:
    def __init__(self, *_args, **_kwargs) -> None:
        self.calls = 0

    async def dispatch_intent(self, _intent):
        self.calls += 1
        return SimpleNamespace(succeeded=1)


@pytest.mark.asyncio
async def test_dispatch_skips_impossible_travel_without_user_identity(monkeypatch) -> None:
    import graph_ingress.dispatcher as dispatcher_module

    monkeypatch.setattr(dispatcher_module, "RouteFanoutDispatcher", _FakeFanout)

    dispatcher = TemporalGraphIngressDispatcher()

    async def _fake_get_client():
        return None

    dispatcher._get_client = _fake_get_client  # type: ignore[method-assign, assignment]

    notifications = [
        {
            "subscriptionId": "sub-1",
            "changeType": "updated",
            "resource": "auditLogs/signIns/abc",
            "resourceData": {
                "id": "signin-1",
                "ipAddress": "10.0.0.1",
            },
        }
    ]

    model_notifications = [
        dispatcher_module.GraphNotificationItem.model_validate(item) for item in notifications
    ]

    result = await dispatcher.dispatch("tenant-1", model_notifications)

    assert result == "dispatched=0,ignored=1"
