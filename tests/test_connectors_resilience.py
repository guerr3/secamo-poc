from __future__ import annotations

from typing import Any

import pytest

from connectors.jira import JiraConnector
from connectors.microsoft_defender import MicrosoftGraphConnector
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


@pytest.mark.asyncio
async def test_graph_get_device_context_uses_defender_token(mocker, graph_secrets):
    queue = [_Resp(200, body={"id": "machine-1", "computerDnsName": "host-1", "osPlatform": "Windows", "riskScore": "Medium"})]
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
    result = await connector.execute_action("get_device_context", {"device_id": "machine-1"})

    assert result["found"] is True
    assert result["device_id"] == "machine-1"
    assert result["display_name"] == "host-1"
    defender_token.assert_awaited_once()
    graph_token.assert_not_awaited()


@pytest.mark.asyncio
async def test_graph_get_identity_risk_uses_graph_token(mocker, graph_secrets):
    queue = [
        _Resp(
            200,
            body={
                "value": [
                    {
                        "userPrincipalName": "alice@example.com",
                        "riskLevel": "high",
                        "riskState": "atRisk",
                        "riskDetail": "adminConfirmedSigninCompromised",
                    }
                ]
            },
        )
    ]
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
    result = await connector.execute_action("get_identity_risk", {"lookup_key": "alice@example.com"})

    assert result["found"] is True
    assert result["subject"] == "alice@example.com"
    assert result["risk_level"] == "high"
    graph_token.assert_awaited_once()
    defender_token.assert_not_awaited()


@pytest.mark.asyncio
async def test_graph_phase1_identity_actions_use_graph_token(mocker, graph_secrets):
    queue = [
        _Resp(200, body={"value": [{"id": "risk-1", "riskLevel": "high"}]}),
        _Resp(200, body={"value": [{"id": "signin-1"}]}),
        _Resp(204, body={}, content=b""),
        _Resp(204, body={}, content=b""),
    ]
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
    risky = await connector.execute_action("list_risky_users", {"min_risk_level": "medium"})
    signins = await connector.execute_action(
        "get_signin_history",
        {"user_principal_name": "alice@example.com", "top": 10},
    )
    confirmed = await connector.execute_action("confirm_user_compromised", {"user_id": "u-1"})
    dismissed = await connector.execute_action("dismiss_risky_user", {"user_id": "u-1"})

    assert risky["users"][0]["id"] == "risk-1"
    assert signins["signins"][0]["id"] == "signin-1"
    assert confirmed["confirmed"] is True
    assert dismissed["dismissed"] is True
    assert all(call["headers"]["Authorization"] == "Bearer graph-tok" for call in calls)
    defender_token.assert_not_awaited()


@pytest.mark.asyncio
async def test_graph_phase1_device_actions_use_defender_token(mocker, graph_secrets):
    queue = [
        _Resp(202, body={"status": "submitted"}, content=b'{"status":"submitted"}'),
        _Resp(202, body={"status": "submitted"}, content=b'{"status":"submitted"}'),
    ]
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
    scan = await connector.execute_action("run_antivirus_scan", {"device_id": "machine-1", "scan_type": "quick"})
    unisolate = await connector.execute_action("unisolate_device", {"device_id": "machine-1"})

    assert scan["submitted"] is True
    assert unisolate["status"] == "submitted"
    assert all(call["headers"]["Authorization"] == "Bearer defender-tok" for call in calls)
    graph_token.assert_not_awaited()


@pytest.mark.asyncio
async def test_graph_subscription_actions_use_graph_token(mocker, graph_secrets):
    queue = [
        _Resp(201, body={"id": "sub-1", "resource": "security/alerts_v2", "expirationDateTime": "2026-03-31T01:00:00Z", "notificationUrl": "https://hook", "clientState": "secamo:t1:alerts"}),
        _Resp(200, body={"id": "sub-1", "resource": "security/alerts_v2", "expirationDateTime": "2026-03-31T02:00:00Z", "notificationUrl": "https://hook", "clientState": "secamo:t1:alerts"}),
        _Resp(200, body={"value": [{"id": "sub-1", "resource": "security/alerts_v2", "clientState": "secamo:t1:alerts"}]}),
        _Resp(204, body={}, content=b""),
    ]
    calls: list[dict[str, Any]] = []

    graph_token = mocker.AsyncMock(return_value="graph-tok")
    mocker.patch("connectors.microsoft_defender.get_graph_token", new=graph_token)
    mocker.patch("connectors.microsoft_defender.get_defender_token", new=mocker.AsyncMock(return_value="defender-tok"))
    mocker.patch(
        "connectors.microsoft_defender.httpx.AsyncClient",
        side_effect=lambda **kwargs: _Client(queue, calls),
    )

    connector = MicrosoftGraphConnector(tenant_id="tenant-1", secrets=graph_secrets)
    created = await connector.execute_action(
        "create_subscription",
        {
            "resource": "security/alerts_v2",
            "change_types": ["created", "updated"],
            "notification_url": "https://hook",
            "client_state": "secamo:t1:alerts",
            "expiration_minutes": 60,
        },
    )
    renewed = await connector.execute_action("renew_subscription", {"subscription_id": "sub-1", "expiration_minutes": 90})
    listed = await connector.execute_action("list_subscriptions", {})
    deleted = await connector.execute_action("delete_subscription", {"subscription_id": "sub-1"})

    assert created["id"] == "sub-1"
    assert renewed["id"] == "sub-1"
    assert listed["subscriptions"][0]["id"] == "sub-1"
    assert deleted["deleted"] is True
    assert all(call["headers"]["Authorization"] == "Bearer graph-tok" for call in calls)


@pytest.mark.asyncio
async def test_graph_send_email_action_uses_graph_token(mocker, graph_secrets):
    queue = [_Resp(202, body={}, headers={"x-ms-request-id": "mail-1"}, content=b"")]
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
    result = await connector.execute_action(
        "send_email",
        {
            "sender": "sender@example.com",
            "to": "dest@example.com",
            "subject": "Subject",
            "body": "Body",
            "content_type": "Text",
        },
    )

    assert result["sent"] is True
    assert result["message_id"] == "mail-1"
    assert calls[0]["headers"]["Authorization"] == "Bearer graph-tok"
    graph_token.assert_awaited_once()
    defender_token.assert_not_awaited()


@pytest.mark.asyncio
async def test_jira_create_ticket_uses_secret_project_key_fallback(mocker, jira_secrets):
    queue = [_Resp(201, body={"key": "SOC-101"}, content=b'{"key":"SOC-101"}')]
    calls: list[dict[str, Any]] = []

    secrets_with_project = jira_secrets.model_copy(update={"project_key": "TENANTSOC"})
    mocker.patch(
        "connectors.jira.httpx.AsyncClient",
        side_effect=lambda **kwargs: _Client(queue, calls),
    )

    connector = JiraConnector(tenant_id="tenant-1", secrets=secrets_with_project)
    result = await connector.execute_action(
        "create_ticket",
        {"title": "Example", "description": "Desc", "issue_type": "Incident"},
    )

    assert result["key"] == "SOC-101"
    assert calls[0]["json"]["fields"]["project"]["key"] == "TENANTSOC"
