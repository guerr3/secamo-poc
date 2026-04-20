from __future__ import annotations

from typing import Any

import pytest

from connectors.errors import ConnectorPermanentError
from connectors.jira import JiraConnector
from connectors.microsoft import MicrosoftApiTransport, MicrosoftDefenderEDRConnector
from shared.models import DefenderSecuritySignalEvent
from shared.providers.contracts import TenantSecrets


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


class _TransportStub:
    def __init__(
        self,
        *,
        graph_queue: list[_Resp | Exception] | None = None,
        defender_queue: list[_Resp | Exception] | None = None,
    ) -> None:
        self._graph_queue = list(graph_queue or [])
        self._defender_queue = list(defender_queue or [])
        self.graph_calls: list[dict[str, Any]] = []
        self.defender_calls: list[dict[str, Any]] = []

    async def request_graph(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
    ) -> _Resp:
        self.graph_calls.append({"method": method, "url": url, "params": params, "json": json})
        item = self._graph_queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    async def request_defender(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
    ) -> _Resp:
        self.defender_calls.append({"method": method, "url": url, "params": params, "json": json})
        item = self._defender_queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


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
async def test_microsoft_transport_retries_on_429(mocker, graph_secrets):
    queue = [
        _Resp(429, headers={"Retry-After": "0"}),
        _Resp(200, body={"value": []}),
    ]
    calls: list[dict[str, Any]] = []

    mocker.patch("connectors.microsoft.transport.asyncio.sleep", new=mocker.AsyncMock())
    mocker.patch("connectors.microsoft.transport.get_graph_token", new=mocker.AsyncMock(return_value="tok"))
    mocker.patch(
        "connectors.microsoft.transport.httpx.AsyncClient",
        side_effect=lambda **kwargs: _Client(queue, calls),
    )

    transport = MicrosoftApiTransport(secrets=graph_secrets)
    response = await transport.request_graph("GET", "https://graph.microsoft.com/v1.0/security/alerts_v2")

    assert response.status_code == 200
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_edr_fetch_events_non_defender_maps_to_security_signal(graph_secrets):
    transport = _TransportStub(
        graph_queue=[
            _Resp(
                200,
                body={
                    "value": [
                        {
                            "id": "risk-1",
                            "riskLastUpdatedDateTime": "2026-03-22T00:00:00Z",
                            "riskLevel": "high",
                            "riskState": "atRisk",
                            "userPrincipalName": "alice@example.com",
                        }
                    ]
                },
            )
        ]
    )
    connector = MicrosoftDefenderEDRConnector(
        tenant_id="tenant-1",
        secrets=graph_secrets,
        transport=transport,
    )

    events = await connector.fetch_events({"resource_type": "entra_risky_users", "top": 1})

    assert len(events) == 1
    assert isinstance(events[0].payload, DefenderSecuritySignalEvent)
    assert events[0].payload.event_type == "defender.security_signal"
    assert events[0].payload.provider_event_type == "risky_user"
    assert events[0].payload.resource_type == "entra_risky_users"
    assert "$expand" not in (transport.graph_calls[0]["params"] or {})


@pytest.mark.asyncio
async def test_edr_fetch_events_maps_typed_evidence_fields(graph_secrets):
    transport = _TransportStub(
        graph_queue=[
            _Resp(
                200,
                body={
                    "value": [
                        {
                            "id": "a-evidence-1",
                            "createdDateTime": "2026-03-22T00:00:00Z",
                            "severity": "high",
                            "title": "Alert",
                            "description": "Body",
                            "evidence": [
                                {
                                    "@odata.type": "#microsoft.graph.security.ipEvidence",
                                    "ipAddress": "8.8.8.8",
                                },
                                {
                                    "@odata.type": "#microsoft.graph.security.networkConnectionEvidence",
                                    "sourceAddress": "1.2.3.4",
                                    "destinationAddress": "5.6.7.8",
                                },
                                {
                                    "@odata.type": "#microsoft.graph.security.deviceEvidence",
                                    "deviceId": "device-123",
                                },
                                {
                                    "@odata.type": "#microsoft.graph.security.userEvidence",
                                    "userPrincipalName": "alice@example.com",
                                },
                            ],
                        }
                    ]
                },
            )
        ]
    )
    connector = MicrosoftDefenderEDRConnector(
        tenant_id="tenant-1",
        secrets=graph_secrets,
        transport=transport,
    )

    events = await connector.fetch_events({"resource_type": "defender_alerts", "top": 1})

    payload = events[0].payload
    assert payload.vendor_extensions["source_ip"].value == "8.8.8.8"
    assert payload.vendor_extensions["destination_ip"].value == "5.6.7.8"
    assert payload.vendor_extensions["device_id"].value == "device-123"
    assert payload.vendor_extensions["user_email"].value == "alice@example.com"


@pytest.mark.asyncio
async def test_edr_list_user_alerts_filters_client_side(graph_secrets):
    transport = _TransportStub(
        graph_queue=[
            _Resp(
                200,
                body={
                    "value": [
                        {
                            "id": "a1",
                            "userStates": [{"userPrincipalName": "User@Example.com"}],
                        },
                        {
                            "id": "a2",
                            "evidence": [
                                {
                                    "@odata.type": "#microsoft.graph.security.userEvidence",
                                    "userPrincipalName": "user@example.com",
                                }
                            ],
                        },
                        {
                            "id": "a3",
                            "userStates": [{"userPrincipalName": "other@example.com"}],
                        },
                    ]
                },
            )
        ]
    )
    connector = MicrosoftDefenderEDRConnector(
        tenant_id="tenant-1",
        secrets=graph_secrets,
        transport=transport,
    )

    result = await connector.execute_action("list_user_alerts", {"user_email": "user@example.com"})

    assert [alert["id"] for alert in result["alerts"]] == ["a1", "a2"]
    params = transport.graph_calls[0]["params"] or {}
    assert "$expand" not in params
    assert "createdDateTime gt" in params["$filter"]


@pytest.mark.asyncio
async def test_edr_list_user_alerts_surfaces_400(graph_secrets):
    transport = _TransportStub(
        graph_queue=[
            ConnectorPermanentError("Microsoft API request rejected: status=400 url=https://graph.microsoft.com"),
        ]
    )
    connector = MicrosoftDefenderEDRConnector(
        tenant_id="tenant-1",
        secrets=graph_secrets,
        transport=transport,
    )

    with pytest.raises(ConnectorPermanentError):
        await connector.execute_action("list_user_alerts", {"user_email": "user@example.com"})

    params = transport.graph_calls[0]["params"] or {}
    assert "$filter" in params


@pytest.mark.asyncio
async def test_edr_fetch_events_surfaces_400(graph_secrets):
    transport = _TransportStub(
        graph_queue=[
            ConnectorPermanentError("Microsoft API request rejected: status=400 url=https://graph.microsoft.com"),
        ]
    )
    connector = MicrosoftDefenderEDRConnector(
        tenant_id="tenant-1",
        secrets=graph_secrets,
        transport=transport,
    )

    with pytest.raises(ConnectorPermanentError):
        await connector.fetch_events({"resource_type": "defender_alerts", "top": 1})

    params = transport.graph_calls[0]["params"] or {}
    assert "$filter" in params
