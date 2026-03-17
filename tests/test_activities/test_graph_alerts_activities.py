from __future__ import annotations

import pytest

from activities.graph_alerts import graph_enrich_alert, graph_get_alerts
from activities.graph_devices import graph_isolate_device
from activities.risk import calculate_risk_score
from activities.threat_intel import threat_intel_lookup
from shared.models import AlertData, EnrichedAlert, TenantSecrets, ThreatIntelResult


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
def alert() -> AlertData:
    return AlertData(
        alert_id="a1",
        severity="high",
        title="Test",
        description="Desc",
        user_email="user@example.com",
        device_id="d1",
        source_ip="1.1.1.1",
    )


@pytest.fixture
def secrets() -> TenantSecrets:
    return TenantSecrets(client_id="cid", client_secret="sec", tenant_azure_id="tid")


@pytest.mark.asyncio
async def test_graph_enrich_alert_happy(mocker, alert, secrets):
    mocker.patch("activities.graph_alerts.get_graph_token", return_value="tok")
    responses = [
        _Resp(200, {"severity": "high", "title": "Alert", "description": "Body"}),
        _Resp(200, {"displayName": "User One", "department": "Finance"}),
        _Resp(200, {"deviceName": "LAPTOP-1", "osPlatform": "Windows", "isCompliant": False}),
    ]
    mocker.patch("activities.graph_alerts.httpx.AsyncClient", return_value=_Client(responses))
    enriched = await graph_enrich_alert("t1", alert, secrets)
    assert enriched.user_display_name == "User One"
    assert enriched.device_compliance == "noncompliant"


@pytest.mark.asyncio
async def test_graph_get_alerts_happy_and_error(mocker, secrets):
    mocker.patch("activities.graph_alerts.get_graph_token", return_value="tok")
    mocker.patch("activities.graph_alerts.httpx.AsyncClient", return_value=_Client([_Resp(200, {"value": [{"id": "a1"}]})]))
    alerts = await graph_get_alerts("t1", "user@example.com", secrets)
    assert len(alerts) == 1

    mocker.patch("activities.graph_alerts.httpx.AsyncClient", return_value=_Client([_Resp(404)]))
    alerts404 = await graph_get_alerts("t1", "user@example.com", secrets)
    assert alerts404 == []


@pytest.mark.asyncio
async def test_graph_isolate_device_happy(mocker, secrets):
    mocker.patch("activities.graph_devices.get_defender_token", return_value="tok")
    mocker.patch("activities.graph_devices.httpx.AsyncClient", return_value=_Client([_Resp(201)]))
    assert await graph_isolate_device("t1", "d1", secrets) is True


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
