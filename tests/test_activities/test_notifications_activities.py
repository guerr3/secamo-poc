from __future__ import annotations

import pytest
from temporalio.exceptions import ApplicationError

from activities.communications import email_send, teams_send_adaptive_card, teams_send_notification
from shared.providers.contracts import TenantSecrets


class _Resp:
    def __init__(self, status: int, headers: dict | None = None):
        self.status_code = status
        self.headers = headers or {}


class _Client:
    def __init__(self, resp: _Resp):
        self.resp = resp

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, *args, **kwargs):
        return self.resp


@pytest.mark.asyncio
async def test_teams_send_notification_happy(mocker):
    mocker.patch("activities.communications.httpx.AsyncClient", return_value=_Client(_Resp(200, {"x-ms-request-id": "m1"})))
    res = await teams_send_notification("t1", "https://example.webhook", "hello")
    assert res.success is True


@pytest.mark.asyncio
async def test_teams_send_notification_loads_fallback_webhook_from_tenant_secrets(mocker):
    mocker.patch("activities._tenant_secrets.load_tenant_secrets", return_value=TenantSecrets(client_id="c", client_secret="s", tenant_azure_id="t", teams_webhook_url="https://fallback.webhook"))
    mocker.patch("activities.communications.httpx.AsyncClient", return_value=_Client(_Resp(200, {"x-ms-request-id": "m2"})))
    res = await teams_send_notification("t1", "", "hello")
    assert res.success is True


@pytest.mark.asyncio
async def test_teams_send_adaptive_card_error(mocker):
    mocker.patch("activities.communications.httpx.AsyncClient", return_value=_Client(_Resp(500)))
    with pytest.raises(ApplicationError):
        await teams_send_adaptive_card("t1", "https://example.webhook", {"type": "AdaptiveCard"})


@pytest.mark.asyncio
async def test_email_send_happy(mocker):
    mocker.patch("activities.communications._load_graph_secrets_async", return_value=TenantSecrets(client_id="c", client_secret="s", tenant_azure_id="t"))
    mocker.patch(
        "activities.communications.connector_execute_action",
        new=mocker.AsyncMock(
            return_value=type("_ActionResult", (), {
                "data": type("_Data", (), {"payload": {"message_id": "x1", "sent": True}})(),
            })()
        ),
    )
    res = await email_send("t1", "dest@example.com", "Subject", "Body")
    assert res.success is True
