"""Phase-5 verification for route registry and best-effort fan-out behavior.

Responsibility: validate multi-route resolution and continuation on per-route dispatch failure.
This module must not test provider payload normalization internals.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import pytest

from shared.models.canonical import (
    Correlation,
    DefenderDetectionFindingEvent,
    Envelope,
    HitlApprovalEvent,
    ImpossibleTravelEvent,
    StoragePartition,
)
from shared.routing.defaults import build_default_route_registry
from shared.routing.contracts import WorkflowRoute
from shared.routing.registry import RouteRegistry, UnroutableEventError


class _DispatchSpy:
    def __init__(self, failing_workflow: str | None = None) -> None:
        self.failing_workflow = failing_workflow
        self.calls: list[str] = []

    async def dispatch(self, route: WorkflowRoute, envelope: Envelope) -> None:
        self.calls.append(route.workflow_name)
        if self.failing_workflow and route.workflow_name == self.failing_workflow:
            raise RuntimeError("dispatch_failed")


def _sample_envelope() -> Envelope:
    return Envelope(
        event_id="evt-1",
        tenant_id="tenant-1",
        source_provider="microsoft_defender",
        event_name="defender.alert",
        schema_version="1.0.0",
        event_version="1.0.0",
        ocsf_version="1.1.0",
        occurred_at=datetime.now(timezone.utc),
        correlation=Correlation(
            correlation_id="corr-1",
            causation_id="corr-1",
            request_id="req-1",
            trace_id="trace-1",
            storage_partition=StoragePartition(
                ddb_pk="TENANT#tenant-1",
                ddb_sk="EVENT#defender#alert#a-1",
                s3_bucket="secamo-events-tenant-1",
                s3_key_prefix="raw/defender.alert/a-1",
            ),
        ),
        payload=DefenderDetectionFindingEvent(
            event_type="defender.alert",
            activity_id=2004,
            alert_id="a-1",
            title="Suspicious sign-in",
            severity_id=60,
            severity="high",
        ),
    )


def test_route_registry_resolves_multiple_routes() -> None:
    registry = RouteRegistry()
    registry.register(
        "microsoft_defender",
        "defender.alert",
        (
            WorkflowRoute(workflow_name="DefenderAlertEnrichmentWorkflow", task_queue="soc-defender"),
            WorkflowRoute(workflow_name="IncidentCorrelatorWorkflow", task_queue="soc-defender"),
        ),
    )

    resolved = registry.resolve(_sample_envelope())
    assert len(resolved) == 2
    assert resolved[0].workflow_name == "DefenderAlertEnrichmentWorkflow"
    assert resolved[1].workflow_name == "IncidentCorrelatorWorkflow"


def test_route_registry_resolves_provider_specific_fallbacks() -> None:
    registry = RouteRegistry()
    registry.register(
        "microsoft_defender",
        "defender.alert",
        (WorkflowRoute(workflow_name="DefenderAlertEnrichmentWorkflow", task_queue="soc-defender"),),
    )
    registry.register(
        "crowdstrike",
        "defender.alert",
        (WorkflowRoute(workflow_name="CrowdStrikeSpecificWorkflow", task_queue="soc-defender"),),
    )

    defender_envelope = _sample_envelope()
    crowdstrike_envelope = defender_envelope.model_copy(update={"source_provider": "crowdstrike"})

    defender_route = registry.resolve(defender_envelope)
    crowdstrike_route = registry.resolve(crowdstrike_envelope)

    assert defender_route[0].workflow_name == "DefenderAlertEnrichmentWorkflow"
    assert crowdstrike_route[0].workflow_name == "CrowdStrikeSpecificWorkflow"


@pytest.mark.asyncio
async def test_best_effort_fanout_continues_on_failure(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("tests.routing")
    registry = RouteRegistry(logger=logger)
    registry.register(
        "microsoft_defender",
        "defender.alert",
        (
            WorkflowRoute(workflow_name="WorkflowA", task_queue="soc-defender"),
            WorkflowRoute(workflow_name="WorkflowB", task_queue="soc-defender"),
            WorkflowRoute(workflow_name="WorkflowC", task_queue="soc-defender"),
        ),
    )

    dispatcher = _DispatchSpy(failing_workflow="WorkflowB")
    envelope = _sample_envelope()

    with caplog.at_level(logging.ERROR):
        report = await registry.dispatch_best_effort(envelope, dispatcher)

    assert dispatcher.calls == ["WorkflowA", "WorkflowB", "WorkflowC"]
    assert report.attempted == 3
    assert report.succeeded == 2
    assert report.failed == 1
    assert len(report.failures) == 1
    assert report.failures[0].workflow_name == "WorkflowB"

    combined_logs = "\n".join(caplog.messages)
    assert "[fan-out error] workflow=WorkflowB tenant=tenant-1 reason=dispatch_failed" in combined_logs
    assert "provider=microsoft_defender" in combined_logs
    assert "event_type=defender.alert" in combined_logs


@pytest.mark.asyncio
async def test_unknown_route_key_raises_unroutable_error() -> None:
    registry = RouteRegistry()
    dispatcher = _DispatchSpy()
    envelope = Envelope(
        event_id="evt-2",
        tenant_id="tenant-1",
        source_provider="unknown_provider",
        event_name="unknown_event",
        schema_version="1.0.0",
        event_version="1.0.0",
        ocsf_version="1.1.0",
        occurred_at=datetime.now(timezone.utc),
        correlation=Correlation(
            correlation_id="corr-2",
            causation_id="corr-2",
            request_id="req-2",
            trace_id="trace-2",
            storage_partition=StoragePartition(
                ddb_pk="TENANT#tenant-1",
                ddb_sk="EVENT#unknown#event#evt-2",
                s3_bucket="secamo-events-tenant-1",
                s3_key_prefix="raw/unknown_event/evt-2",
            ),
        ),
        payload=ImpossibleTravelEvent(
            event_type="defender.impossible_travel",
            activity_id=3002,
            user_principal_name="unknown@example.com",
            source_ip="10.0.0.1",
            severity_id=20,
        ),
    )

    with pytest.raises(UnroutableEventError):
        await registry.dispatch_best_effort(envelope, dispatcher)

    assert dispatcher.calls == []


def test_default_registry_does_not_start_workflow_for_hitl_approval() -> None:
    registry = build_default_route_registry()
    envelope = Envelope(
        event_id="evt-hitl-1",
        tenant_id="tenant-1",
        source_provider="microsoft_graph",
        event_name="hitl.approval",
        schema_version="1.0.0",
        event_version="1.0.0",
        ocsf_version="1.1.0",
        occurred_at=datetime.now(timezone.utc),
        correlation=Correlation(
            correlation_id="corr-hitl-1",
            causation_id="corr-hitl-1",
            request_id="req-hitl-1",
            trace_id="trace-hitl-1",
            storage_partition=StoragePartition(
                ddb_pk="TENANT#tenant-1",
                ddb_sk="EVENT#hitl#approval#evt-hitl-1",
                s3_bucket="secamo-events-tenant-1",
                s3_key_prefix="raw/hitl.approval/evt-hitl-1",
            ),
        ),
        payload=HitlApprovalEvent(
            event_type="hitl.approval",
            activity_id=9001,
            activity_name="hitl_response",
            approval_id="wf-123",
            decision="approved",
            channel="web",
            responder="analyst@example.com",
        ),
    )

    with pytest.raises(UnroutableEventError):
        registry.resolve(envelope)
