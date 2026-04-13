from __future__ import annotations

from typing import Any

import pytest

from connectors.errors import ConnectorPermanentError
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
    assert calls[0]["params"]["$expand"] == "evidence"


@pytest.mark.asyncio
async def test_graph_fetch_events_non_defender_does_not_expand_evidence(mocker, graph_secrets):
    queue = [
        _Resp(
            200,
            body={
                "value": [
                    {
                        "id": "s1",
                        "createdDateTime": "2026-03-22T00:00:00Z",
                        "userPrincipalName": "alice@example.com",
                        "ipAddress": "10.0.0.1",
                    }
                ]
            },
        ),
    ]
    calls: list[dict[str, Any]] = []

    mocker.patch("connectors.microsoft_defender.get_graph_token", new=mocker.AsyncMock(return_value="tok"))
    mocker.patch(
        "connectors.microsoft_defender.httpx.AsyncClient",
        side_effect=lambda **kwargs: _Client(queue, calls),
    )

    connector = MicrosoftGraphConnector(tenant_id="tenant-1", secrets=graph_secrets)
    events = await connector.fetch_events({"resource_type": "entra_signin_logs", "top": 1})

    assert len(events) == 1
    assert "$expand" not in calls[0]["params"]


@pytest.mark.asyncio
async def test_graph_fetch_events_maps_typed_evidence_fields(mocker, graph_secrets):
    queue = [
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
        ),
    ]
    calls: list[dict[str, Any]] = []

    mocker.patch("connectors.microsoft_defender.get_graph_token", new=mocker.AsyncMock(return_value="tok"))
    mocker.patch(
        "connectors.microsoft_defender.httpx.AsyncClient",
        side_effect=lambda **kwargs: _Client(queue, calls),
    )

    connector = MicrosoftGraphConnector(tenant_id="tenant-1", secrets=graph_secrets)
    events = await connector.fetch_events({"resource_type": "defender_alerts", "top": 1})

    payload = events[0].payload
    assert payload.vendor_extensions["source_ip"].value == "8.8.8.8"
    assert payload.vendor_extensions["destination_ip"].value == "5.6.7.8"
    assert payload.vendor_extensions["device_id"].value == "device-123"
    assert payload.vendor_extensions["user_email"].value == "alice@example.com"


@pytest.mark.asyncio
async def test_graph_fetch_events_handles_empty_evidence_fields(mocker, graph_secrets):
    queue = [
        _Resp(
            200,
            body={
                "value": [
                    {
                        "id": "a-evidence-2",
                        "createdDateTime": "2026-03-22T00:00:00Z",
                        "severity": "medium",
                        "title": "Alert without evidence",
                        "description": "Body",
                        "evidence": [],
                    }
                ]
            },
        ),
    ]
    calls: list[dict[str, Any]] = []

    mocker.patch("connectors.microsoft_defender.get_graph_token", new=mocker.AsyncMock(return_value="tok"))
    mocker.patch(
        "connectors.microsoft_defender.httpx.AsyncClient",
        side_effect=lambda **kwargs: _Client(queue, calls),
    )

    connector = MicrosoftGraphConnector(tenant_id="tenant-1", secrets=graph_secrets)
    events = await connector.fetch_events({"resource_type": "defender_alerts", "top": 1})

    payload = events[0].payload
    assert payload.vendor_extensions["source_ip"].value is None
    assert payload.vendor_extensions["destination_ip"].value is None
    assert payload.vendor_extensions["device_id"].value is None
    assert payload.vendor_extensions["user_email"].value is None


@pytest.mark.asyncio
async def test_graph_list_user_alerts_filters_client_side(mocker, graph_secrets):
    queue = [
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
    calls: list[dict[str, Any]] = []

    mocker.patch("connectors.microsoft_defender.get_graph_token", new=mocker.AsyncMock(return_value="tok"))
    mocker.patch(
        "connectors.microsoft_defender.httpx.AsyncClient",
        side_effect=lambda **kwargs: _Client(queue, calls),
    )

    connector = MicrosoftGraphConnector(tenant_id="tenant-1", secrets=graph_secrets)
    result = await connector.execute_action("list_user_alerts", {"user_email": "user@example.com"})

    assert [alert["id"] for alert in result["alerts"]] == ["a1", "a2"]
    assert calls[0]["params"]["$expand"] == "evidence"
    assert "createdDateTime gt" in calls[0]["params"]["$filter"]


@pytest.mark.asyncio
async def test_graph_list_user_alerts_fallback_on_400(mocker, graph_secrets):
    queue = [
        _Resp(400, body={"error": {"message": "Unsupported filter"}}),
        _Resp(
            200,
            body={
                "value": [
                    {
                        "id": "a1",
                        "userStates": [{"userPrincipalName": "user@example.com"}],
                    }
                ]
            },
        ),
    ]
    calls: list[dict[str, Any]] = []

    mocker.patch("connectors.microsoft_defender.get_graph_token", new=mocker.AsyncMock(return_value="tok"))
    mocker.patch(
        "connectors.microsoft_defender.httpx.AsyncClient",
        side_effect=lambda **kwargs: _Client(queue, calls),
    )

    connector = MicrosoftGraphConnector(tenant_id="tenant-1", secrets=graph_secrets)
    result = await connector.execute_action("list_user_alerts", {"user_email": "user@example.com"})

    assert [alert["id"] for alert in result["alerts"]] == ["a1"]
    assert "$filter" in calls[0]["params"]
    assert "$filter" not in calls[1]["params"]
    assert calls[1]["params"]["$expand"] == "evidence"


@pytest.mark.asyncio
async def test_graph_fetch_events_defender_fallback_removes_filter_on_400(mocker, graph_secrets):
    queue = [
        _Resp(400, body={"error": {"message": "Unsupported filter"}}),
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

    mocker.patch("connectors.microsoft_defender.get_graph_token", new=mocker.AsyncMock(return_value="tok"))
    mocker.patch(
        "connectors.microsoft_defender.httpx.AsyncClient",
        side_effect=lambda **kwargs: _Client(queue, calls),
    )

    connector = MicrosoftGraphConnector(tenant_id="tenant-1", secrets=graph_secrets)
    events = await connector.fetch_events({"resource_type": "defender_alerts", "top": 1})

    assert len(events) == 1
    assert "$filter" in calls[0]["params"]
    assert "$filter" not in calls[1]["params"]
    assert calls[1]["params"]["$expand"] == "evidence"


@pytest.mark.asyncio
async def test_graph_fetch_events_defender_fallback_removes_expand_after_second_400(mocker, graph_secrets):
    queue = [
        _Resp(400, body={"error": {"message": "Unsupported filter"}}),
        _Resp(400, body={"error": {"message": "Unsupported expand"}}),
        _Resp(
            200,
            body={
                "value": [
                    {
                        "id": "a2",
                        "createdDateTime": "2026-03-22T00:00:00Z",
                        "severity": "medium",
                        "title": "Alert without expand",
                    }
                ]
            },
        ),
    ]
    calls: list[dict[str, Any]] = []

    mocker.patch("connectors.microsoft_defender.get_graph_token", new=mocker.AsyncMock(return_value="tok"))
    mocker.patch(
        "connectors.microsoft_defender.httpx.AsyncClient",
        side_effect=lambda **kwargs: _Client(queue, calls),
    )

    connector = MicrosoftGraphConnector(tenant_id="tenant-1", secrets=graph_secrets)
    events = await connector.fetch_events({"resource_type": "defender_alerts", "top": 1})

    assert len(events) == 1
    assert "$filter" in calls[0]["params"]
    assert "$filter" not in calls[1]["params"]
    assert "$expand" in calls[1]["params"]
    assert "$expand" not in calls[2]["params"]


@pytest.mark.asyncio
async def test_graph_enrich_alert_context_fallback_removes_expand_on_400(mocker, graph_secrets):
    queue = [
        _Resp(400, body={"error": {"message": "Unsupported expand"}}),
        _Resp(
            200,
            body={
                "id": "a1",
                "severity": "high",
                "title": "Alert title",
                "description": "Alert body",
                "evidence": [],
            },
        ),
    ]
    calls: list[dict[str, Any]] = []

    mocker.patch("connectors.microsoft_defender.get_graph_token", new=mocker.AsyncMock(return_value="tok"))
    mocker.patch(
        "connectors.microsoft_defender.httpx.AsyncClient",
        side_effect=lambda **kwargs: _Client(queue, calls),
    )

    connector = MicrosoftGraphConnector(tenant_id="tenant-1", secrets=graph_secrets)
    result = await connector.execute_action("enrich_alert_context", {"alert_id": "a1"})

    assert result["success"] is True
    assert result["alert_id"] == "a1"
    assert result["title"] == "Alert title"
    assert result["description"] == "Alert body"
    assert calls[0]["params"]["$expand"] == "evidence"
    assert calls[1]["params"] is None


@pytest.mark.asyncio
async def test_graph_enrich_alert_context_404_returns_payload_defaults(mocker, graph_secrets):
    queue = [_Resp(404, body={"error": {"message": "Not found"}})]
    calls: list[dict[str, Any]] = []

    mocker.patch("connectors.microsoft_defender.get_graph_token", new=mocker.AsyncMock(return_value="tok"))
    mocker.patch(
        "connectors.microsoft_defender.httpx.AsyncClient",
        side_effect=lambda **kwargs: _Client(queue, calls),
    )

    connector = MicrosoftGraphConnector(tenant_id="tenant-1", secrets=graph_secrets)
    result = await connector.execute_action("enrich_alert_context", {"alert_id": "missing-id"})

    assert result["success"] is True
    assert result["alert_id"] == "missing-id"
    assert calls[0]["params"]["$expand"] == "evidence"


@pytest.mark.asyncio
async def test_graph_enrich_alert_context_device_lookup_400_is_best_effort(mocker, graph_secrets):
    queue = [
        _Resp(
            200,
            body={
                "id": "a1",
                "severity": "medium",
                "title": "Alert title",
                "description": "Alert body",
                "evidence": [
                    {
                        "@odata.type": "#microsoft.graph.security.deviceEvidence",
                        "deviceId": "426eb33370cafb6318ad109b4b0e89b21fd3ae02",
                    }
                ],
            },
        ),
        _Resp(400, body={"error": {"message": "Bad Request"}}),
    ]
    calls: list[dict[str, Any]] = []

    mocker.patch("connectors.microsoft_defender.get_graph_token", new=mocker.AsyncMock(return_value="tok"))
    mocker.patch(
        "connectors.microsoft_defender.httpx.AsyncClient",
        side_effect=lambda **kwargs: _Client(queue, calls),
    )

    connector = MicrosoftGraphConnector(tenant_id="tenant-1", secrets=graph_secrets)
    result = await connector.execute_action("enrich_alert_context", {"alert_id": "a1"})

    assert result["success"] is True
    assert result["alert_id"] == "a1"
    assert result["device_display_name"] is None
    assert result["device_os"] is None
    assert result["device_compliance"] is None
    assert calls[1]["url"].startswith("https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/")


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


@pytest.mark.asyncio
async def test_jira_create_ticket_uses_jsm_customer_request_endpoint(mocker, jira_secrets):
    queue = [
        _Resp(
            201,
            body={
                "issueKey": "HELP-101",
                "serviceDeskId": "42",
                "requestTypeId": "10001",
            },
            content=b'{"issueKey":"HELP-101"}',
        )
    ]
    calls: list[dict[str, Any]] = []

    jsm_secrets = jira_secrets.model_copy(
        update={
            "project_type": "jsm",
            "jsm_service_desk_id": "42",
            "jsm_request_type_id": "10001",
        }
    )
    mocker.patch(
        "connectors.jira.httpx.AsyncClient",
        side_effect=lambda **kwargs: _Client(queue, calls),
    )

    connector = JiraConnector(tenant_id="tenant-1", secrets=jsm_secrets)
    result = await connector.execute_action(
        "create_ticket",
        {
            "title": "Need access",
            "description": "Please grant access",
        },
    )

    assert result["issueKey"] == "HELP-101"
    assert calls[0]["url"].endswith("/rest/servicedeskapi/request")
    assert calls[0]["json"]["serviceDeskId"] == "42"
    assert calls[0]["json"]["requestTypeId"] == "10001"
    assert calls[0]["json"]["requestFieldValues"]["summary"] == "Need access"


@pytest.mark.asyncio
async def test_jira_create_ticket_jsm_requires_request_type_id(mocker, jira_secrets):
    jsm_secrets = jira_secrets.model_copy(
        update={
            "project_type": "jsm",
            "jsm_service_desk_id": "42",
            "jsm_request_type_id": None,
        }
    )
    connector = JiraConnector(tenant_id="tenant-1", secrets=jsm_secrets)

    with pytest.raises(ConnectorPermanentError):
        await connector.execute_action(
            "create_ticket",
            {
                "title": "Need access",
                "description": "Please grant access",
            },
        )


@pytest.mark.asyncio
async def test_jira_update_issue_handles_fields_comment_and_transition(mocker, jira_secrets):
    queue = [
        _Resp(204, body={}, content=b""),
        _Resp(201, body={"id": "1001"}, content=b'{"id":"1001"}'),
        _Resp(200, body={"transitions": [{"id": "31", "name": "Escalated"}]}, content=b'{"transitions":[{"id":"31","name":"Escalated"}]}'),
        _Resp(204, body={}, content=b""),
    ]
    calls: list[dict[str, Any]] = []

    mocker.patch(
        "connectors.jira.httpx.AsyncClient",
        side_effect=lambda **kwargs: _Client(queue, calls),
    )

    connector = JiraConnector(tenant_id="tenant-1", secrets=jira_secrets)
    result = await connector.execute_action(
        "update_issue",
        {
            "ticket_id": "SOC-123",
            "fields": {
                "description": "Updated details",
                "labels": ["secamo", "wf-05"],
            },
            "comment": "Escalated for analyst review",
            "transition_name": "Escalated",
        },
    )

    assert result["updated"] is True
    assert calls[0]["method"] == "PUT"
    assert calls[0]["url"].endswith("/rest/api/3/issue/SOC-123")
    assert calls[1]["method"] == "POST"
    assert calls[1]["url"].endswith("/rest/api/3/issue/SOC-123/comment")
    assert calls[2]["method"] == "GET"
    assert calls[2]["url"].endswith("/rest/api/3/issue/SOC-123/transitions")
    assert calls[3]["method"] == "POST"
    assert calls[3]["json"]["transition"]["id"] == "31"
