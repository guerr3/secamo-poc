from __future__ import annotations

from typing import Any

import pytest

from connectors.jira import JiraConnector
from connectors.microsoft_defender import MicrosoftGraphConnector
from shared.models import TenantSecrets


class _Resp:
    def __init__(
        self,
        status: int,
        body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        content: bytes = b"{}",
    ):
        self.status_code = status
        self._body = body or {}
        self.headers = headers or {}
        self.content = content

    def json(self) -> dict[str, Any]:
        return self._body

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise Exception(f"status={self.status_code}")


class _Client:
    def __init__(self, queue: list[_Resp], calls: list[dict[str, Any]]):
        self._queue = queue
        self._calls = calls

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def request(self, method: str, url: str, **kwargs):
        self._calls.append({"method": method, "url": url, **kwargs})
        return self._queue.pop(0)


@pytest.fixture
def jira_secrets() -> TenantSecrets:
    return TenantSecrets(
        tenant_azure_id="tenant-1",
        client_id="client-id",
        client_secret="client-secret",
        jira_base_url="https://jira.example.com",
        jira_email="user@example.com",
        jira_api_token="token",
    )


@pytest.fixture
def graph_secrets() -> TenantSecrets:
    return TenantSecrets(
        tenant_azure_id="tenant-1",
        client_id="client-id",
        client_secret="client-secret",
    )


@pytest.mark.asyncio
async def test_jira_fetch_events_retries_on_429(mocker, jira_secrets):
    queue = [
        _Resp(429, headers={"Retry-After": "0"}),
        _Resp(200, body={"issues": []}),
    ]
    calls: list[dict[str, Any]] = []

    mocker.patch("connectors.jira.asyncio.sleep", new=mocker.AsyncMock())
    mocker.patch(
        "connectors.jira.httpx.AsyncClient",
        side_effect=lambda **kwargs: _Client(queue, calls),
    )

    connector = JiraConnector(tenant_id="tenant-1", secrets=jira_secrets)
    events = await connector.fetch_events({"top": 5})

    assert events == []
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_graph_fetch_events_retries_on_429(mocker, graph_secrets):
    queue = [
        _Resp(429, headers={"Retry-After": "0"}),
        _Resp(
            200,
            body={
                "value": [
                    {
                        "id": "a1",
                        "createdDateTime": "2026-03-22T00:00:00Z",
                        "severity": "high",
                        "title": "Alert",
                    }
                ]
            },
        ),
    ]
    calls: list[dict[str, Any]] = []

    mocker.patch("connectors.microsoft_defender.asyncio.sleep", new=mocker.AsyncMock())
    mocker.patch("connectors.microsoft_defender.get_graph_token", new=mocker.AsyncMock(return_value="tok"))
    mocker.patch(
        "connectors.microsoft_defender.httpx.AsyncClient",
        side_effect=lambda **kwargs: _Client(queue, calls),
    )

    connector = MicrosoftGraphConnector(tenant_id="tenant-1", secrets=graph_secrets)
    events = await connector.fetch_events({"resource_type": "defender_alerts", "top": 1})

    assert len(events) == 1
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_graph_isolate_uses_defender_token(mocker, graph_secrets):
    queue = [_Resp(200, body={"status": "submitted"}, content=b'{"status":"submitted"}')]
    calls: list[dict[str, Any]] = []

    graph_token = mocker.AsyncMock(return_value="graph-tok")
    defender_token = mocker.AsyncMock(return_value="defender-tok")
    mocker.patch("connectors.microsoft_defender.get_graph_token", new=graph_token)
    mocker.patch("connectors.microsoft_defender.get_defender_token", new=defender_token)
    mocker.patch(
        "connectors.microsoft_defender.httpx.AsyncClient",
        side_effect=lambda **kwargs: _Client(queue, calls),
    )

    connector = MicrosoftGraphConnector(tenant_id="tenant-1", secrets=graph_secrets)
    result = await connector.execute_action("isolate_device", {"device_id": "machine-1"})

    assert result["status"] == "submitted"
    defender_token.assert_awaited_once()
    graph_token.assert_not_awaited()
    assert calls[0]["headers"]["Authorization"] == "Bearer defender-tok"
