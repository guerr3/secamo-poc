from __future__ import annotations

import pytest

from activities.notifications import email_send, teams_send_adaptive_card, teams_send_notification
from shared.models import TenantSecrets


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
    mocker.patch("activities.notifications.httpx.AsyncClient", return_value=_Client(_Resp(200, {"x-ms-request-id": "m1"})))
    res = await teams_send_notification("t1", "https://example.webhook", "hello")
    assert res.success is True


@pytest.mark.asyncio
async def test_teams_send_adaptive_card_error(mocker):
    mocker.patch("activities.notifications.httpx.AsyncClient", return_value=_Client(_Resp(500)))
    res = await teams_send_adaptive_card("t1", "https://example.webhook", {"type": "AdaptiveCard"})
    assert res.success is False


@pytest.mark.asyncio
async def test_email_send_happy(mocker):
    mocker.patch("activities.notifications._load_graph_secrets", return_value=TenantSecrets(client_id="c", client_secret="s", tenant_azure_id="t"))
    mocker.patch("activities.notifications.get_graph_token", return_value="tok")
    mocker.patch("activities.notifications.httpx.AsyncClient", return_value=_Client(_Resp(202, {"x-ms-request-id": "x1"})))
    res = await email_send("t1", "dest@example.com", "Subject", "Body")
    assert res.success is True
