from __future__ import annotations

import pytest
from temporalio.exceptions import ApplicationError

from activities.connector_dispatch import (
    graph_confirm_user_compromised,
    graph_enrich_alert,
    graph_get_alerts,
    graph_get_signin_history,
    graph_isolate_device,
    graph_list_noncompliant_devices,
    graph_list_risky_users,
    graph_run_antivirus_scan,
)
from activities.risk import calculate_risk_score
from activities.threat_intel import threat_intel_lookup
from shared.models import ConnectorActionData, ConnectorActionResult, DefenderDetectionFindingEvent, EnrichedAlert, ThreatIntelResult, VendorExtension
from shared.providers.contracts import TenantSecrets


class _Resp:
    def __init__(self, status: int, body: dict | None = None):
        self.status_code = status
        self._body = body or {}

    def json(self):
        return self._body


class _Client:
    def __init__(self, queue: list[_Resp]):
        self.queue = list(queue)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, *args, **kwargs):
        return self.queue.pop(0)

    async def post(self, *args, **kwargs):
        return self.queue.pop(0)


@pytest.fixture
def alert() -> DefenderDetectionFindingEvent:
    return DefenderDetectionFindingEvent(
        event_type="defender.alert",
        activity_id=2004,
        alert_id="a1",
        severity_id=60,
        severity="high",
        title="Test",
        description="Desc",
        vendor_extensions={
            "user_email": VendorExtension(source="test", value="user@example.com"),
            "device_id": VendorExtension(source="test", value="d1"),
            "source_ip": VendorExtension(source="test", value="1.1.1.1"),
        },
    )


@pytest.fixture
def secrets() -> TenantSecrets:
    return TenantSecrets(client_id="cid", client_secret="sec", tenant_azure_id="tid")


@pytest.mark.asyncio
async def test_graph_enrich_alert_happy(mocker, alert, secrets):
    mocker.patch(
        "activities.connector_dispatch.connector_execute_action",
        new=mocker.AsyncMock(
            return_value=ConnectorActionResult(
                provider="microsoft_defender",
                operation_type="action",
                success=True,
                details="ok",
                data=ConnectorActionData(
                    action="enrich_alert_context",
                    payload={
                        "alert_id": "a1",
                        "severity": "high",
                        "title": "Alert",
                        "description": "Body",
                        "user_display_name": "User One",
                        "user_department": "Finance",
                        "device_display_name": "LAPTOP-1",
                        "device_os": "Windows",
                        "device_compliance": "noncompliant",
                    },
                ),
            )
        ),
    )
    enriched = await graph_enrich_alert("t1", alert)
    assert enriched.user_display_name == "User One"
    assert enriched.device_compliance == "noncompliant"


@pytest.mark.asyncio
async def test_graph_get_alerts_happy_and_error(mocker, secrets):
    mocker.patch(
        "activities.connector_dispatch.connector_execute_action",
        new=mocker.AsyncMock(
            return_value=ConnectorActionResult(
                provider="microsoft_defender",
                operation_type="action",
                success=True,
                details="ok",
                data=ConnectorActionData(action="list_user_alerts", payload={"alerts": [{"id": "a1"}]}),
            )
        ),
    )
    alerts = await graph_get_alerts("t1", "user@example.com")
    assert len(alerts) == 1

    mocker.patch(
        "activities.connector_dispatch.connector_execute_action",
        new=mocker.AsyncMock(side_effect=ApplicationError("boom")),
    )
    with pytest.raises(ApplicationError):
        await graph_get_alerts("t1", "user@example.com")


@pytest.mark.asyncio
async def test_graph_isolate_device_happy(mocker, secrets):
    mocker.patch(
        "activities.connector_dispatch.connector_execute_action",
        new=mocker.AsyncMock(
            return_value=ConnectorActionResult(
                provider="microsoft_defender",
                operation_type="action",
                success=True,
                details="ok",
                data=ConnectorActionData(action="isolate_device", payload={"submitted": True, "found": True}),
            )
        ),
    )
    assert await graph_isolate_device("t1", "d1") is True


@pytest.mark.asyncio
async def test_signin_and_device_facades_use_connector_actions(mocker):
    connector = mocker.AsyncMock()
    connector.side_effect = [
        ConnectorActionResult(
            provider="microsoft_defender",
            operation_type="action",
            success=True,
            data=ConnectorActionData(action="confirm_user_compromised", payload={"confirmed": True}),
        ),
        ConnectorActionResult(
            provider="microsoft_defender",
            operation_type="action",
            success=True,
            data=ConnectorActionData(action="get_signin_history", payload={"signins": [{"id": "s1"}]}),
        ),
        ConnectorActionResult(
            provider="microsoft_defender",
            operation_type="action",
            success=True,
            data=ConnectorActionData(action="list_risky_users", payload={"users": [{"id": "r1", "riskLevel": "high"}]}),
        ),
        ConnectorActionResult(
            provider="microsoft_defender",
            operation_type="action",
            success=True,
            data=ConnectorActionData(action="run_antivirus_scan", payload={"submitted": True, "found": True}),
        ),
        ConnectorActionResult(
            provider="microsoft_defender",
            operation_type="action",
            success=True,
            data=ConnectorActionData(action="list_noncompliant_devices", payload={"devices": [{"id": "dev-1"}]}),
        ),
    ]

    mocker.patch("activities.connector_dispatch.connector_execute_action", new=connector)

    assert await graph_confirm_user_compromised("t1", "u1") is True
    assert await graph_get_signin_history("t1", "user@example.com") == [{"id": "s1"}]
    risky = await graph_list_risky_users("t1", "medium")
    assert len(risky) == 1
    assert risky[0].riskLevel == "high"

    scan_result = await graph_run_antivirus_scan("t1", "dev-1", "quick")
    assert scan_result.success is True
    assert scan_result.data.payload["submitted"] is True
    assert await graph_list_noncompliant_devices("t1") == [{"id": "dev-1"}]


@pytest.mark.asyncio
async def test_threat_intel_lookup_paths(mocker):
    assert (await threat_intel_lookup("t1", "")).is_malicious is False

    mocker.patch("activities.threat_intel.get_secret", return_value=None)
    neutral = await threat_intel_lookup("t1", "8.8.8.8")
    assert neutral.provider == "none"

    mocker.patch("activities.threat_intel.get_secret", return_value="vt-key")
    vt_body = {"data": {"attributes": {"last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 2, "undetected": 5}}}}
    mocker.patch("activities.threat_intel.httpx.AsyncClient", return_value=_Client([_Resp(200, vt_body)]))
    vt = await threat_intel_lookup("t1", "8.8.8.8")
    assert vt.provider == "virustotal"

@pytest.mark.asyncio
async def test_calculate_risk_score_formula_async():
    enriched = EnrichedAlert(
        alert_id="a1",
        severity="critical",
        title="A",
        description="B",
        device_compliance="noncompliant",
        user_department="finance",
    )
    ti = ThreatIntelResult(indicator="x", is_malicious=True, provider="vt", reputation_score=50, details="")
    score = await calculate_risk_score("t1", enriched, ti)
    assert score.score == 100.0
    assert score.level == "critical"
