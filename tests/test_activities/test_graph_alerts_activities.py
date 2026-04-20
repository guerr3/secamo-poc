from __future__ import annotations

import pytest
from temporalio.exceptions import ApplicationError

from activities.edr import (
    edr_enrich_alert,
    edr_get_signin_history,
    edr_get_user_alerts,
    edr_isolate_device,
    edr_list_noncompliant_devices,
    edr_run_antivirus_scan,
)
from activities.identity import identity_confirm_user_compromised, identity_list_risky_users
from activities.risk import calculate_risk_score
from activities.threat_intel import threat_intel_lookup
from shared.models import (
    AlertEnrichmentResult,
    AlertSummary,
    ConnectorActionData,
    ConnectorActionResult,
    EnrichedAlert,
    ThreatIntelResult,
)


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


@pytest.mark.asyncio
async def test_edr_enrich_alert_happy(mocker):
    provider = mocker.AsyncMock()
    provider.enrich_alert.return_value = AlertEnrichmentResult(
        provider="microsoft_defender",
        alert_id="a1",
        severity="high",
        title="Alert",
        description="Body",
    )
    mocker.patch("activities.edr._get_provider", new=mocker.AsyncMock(return_value=provider))

    payload = await edr_enrich_alert("t1", "a1")
    assert payload.alert_id == "a1"
    assert payload.severity == "high"


@pytest.mark.asyncio
async def test_edr_get_user_alerts_happy_and_error(mocker):
    provider = mocker.AsyncMock()
    provider.get_user_alerts.return_value = [AlertSummary(alert_id="a1")]
    mocker.patch("activities.edr._get_provider", new=mocker.AsyncMock(return_value=provider))

    alerts = await edr_get_user_alerts("t1", "user@example.com")
    assert len(alerts) == 1
    assert alerts[0].alert_id == "a1"

    provider.get_user_alerts.side_effect = ApplicationError("boom")
    with pytest.raises(ApplicationError):
        await edr_get_user_alerts("t1", "user@example.com")


@pytest.mark.asyncio
async def test_edr_isolate_device_happy(mocker):
    provider = mocker.AsyncMock()
    provider.isolate_device.return_value = ConnectorActionResult(
        provider="edr",
        operation_type="action",
        success=True,
        details="ok",
        data=ConnectorActionData(action="isolate_device", payload={}),
    )
    mocker.patch("activities.edr._get_provider", new=mocker.AsyncMock(return_value=provider))

    result = await edr_isolate_device("t1", "d1")
    assert result.success is True


@pytest.mark.asyncio
async def test_signin_and_device_capabilities_use_provider_methods(mocker):
    provider = mocker.AsyncMock()
    provider.get_signin_history.return_value = []
    provider.run_antivirus_scan.return_value = ConnectorActionResult(
        provider="edr",
        operation_type="action",
        success=True,
        details="submitted",
        data=ConnectorActionData(action="run_antivirus_scan", payload={"submitted": True}),
    )
    provider.list_noncompliant_devices.return_value = []
    mocker.patch("activities.edr._get_provider", new=mocker.AsyncMock(return_value=provider))

    assert await edr_get_signin_history("t1", "user@example.com") == []

    scan_result = await edr_run_antivirus_scan("t1", "dev-1", "quick")
    assert scan_result.success is True
    assert scan_result.data.payload["submitted"] is True
    assert await edr_list_noncompliant_devices("t1") == []


@pytest.mark.asyncio
async def test_identity_risk_capabilities_use_identity_provider(mocker):
    provider = mocker.AsyncMock()
    provider.confirm_user_compromised.return_value = True
    provider.list_risky_users.return_value = [{"subject": "user@example.com", "risk_level": "high"}]
    mocker.patch("activities.identity._get_identity_provider", new=mocker.AsyncMock(return_value=provider))

    assert await identity_confirm_user_compromised("t1", "u1") is True
    risky = await identity_list_risky_users("t1", "medium")
    assert len(risky) == 1


@pytest.mark.asyncio
async def test_threat_intel_lookup_paths(mocker):
    assert (await threat_intel_lookup("t1", "")).is_malicious is False

    provider = mocker.AsyncMock()
    provider.lookup_indicator.return_value = ThreatIntelResult(
        indicator="8.8.8.8",
        is_malicious=False,
        provider="none",
        reputation_score=0.0,
        details="no threat intel configured",
    )
    mocker.patch("activities.threat_intel._get_provider", return_value=provider)
    neutral = await threat_intel_lookup("t1", "8.8.8.8")
    assert neutral.provider == "none"

    provider.lookup_indicator.return_value = ThreatIntelResult(
        indicator="8.8.8.8",
        is_malicious=True,
        provider="virustotal",
        reputation_score=33.33,
        details="VirusTotal reputation lookup",
    )
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
