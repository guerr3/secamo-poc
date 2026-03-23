"""Phase-5 verification for route registry and best-effort fan-out behavior.

Responsibility: validate multi-route resolution and continuation on per-route dispatch failure.
This module must not test provider payload normalization internals.
"""

from __future__ import annotations

import logging

import pytest

from shared.normalization.contracts import WorkflowIntent
from shared.routing.contracts import WorkflowRoute
from shared.routing.registry import RouteRegistry


class _DispatchSpy:
    def __init__(self, failing_workflow: str | None = None) -> None:
        self.failing_workflow = failing_workflow
        self.calls: list[str] = []

    async def dispatch(self, route: WorkflowRoute, intent: WorkflowIntent) -> None:
        self.calls.append(route.workflow_name)
        if self.failing_workflow and route.workflow_name == self.failing_workflow:
            raise RuntimeError("dispatch_failed")


def _sample_intent() -> WorkflowIntent:
    return WorkflowIntent(
        tenant_id="tenant-1",
        provider="microsoft_defender",
        event_type="alert",
        intent_type="security.alert",
        payload={"alert_id": "a-1"},
    )


def test_route_registry_resolves_multiple_routes() -> None:
    registry = RouteRegistry()
    registry.register(
        "microsoft_defender",
        "alert",
        (
            WorkflowRoute(workflow_name="DefenderAlertEnrichmentWorkflow", task_queue="soc-defender"),
            WorkflowRoute(workflow_name="IncidentCorrelatorWorkflow", task_queue="soc-defender"),
        ),
    )

    resolved = registry.resolve("microsoft_defender", "alert")
    assert len(resolved) == 2
    assert resolved[0].workflow_name == "DefenderAlertEnrichmentWorkflow"
    assert resolved[1].workflow_name == "IncidentCorrelatorWorkflow"


@pytest.mark.asyncio
async def test_best_effort_fanout_continues_on_failure(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("tests.routing")
    registry = RouteRegistry(logger=logger)
    registry.register(
        "microsoft_defender",
        "alert",
        (
            WorkflowRoute(workflow_name="WorkflowA", task_queue="soc-defender"),
            WorkflowRoute(workflow_name="WorkflowB", task_queue="soc-defender"),
            WorkflowRoute(workflow_name="WorkflowC", task_queue="soc-defender"),
        ),
    )

    dispatcher = _DispatchSpy(failing_workflow="WorkflowB")
    intent = _sample_intent()

    with caplog.at_level(logging.ERROR):
        report = await registry.dispatch_best_effort(intent, dispatcher)

    assert dispatcher.calls == ["WorkflowA", "WorkflowB", "WorkflowC"]
    assert report.attempted == 3
    assert report.succeeded == 2
    assert report.failed == 1
    assert len(report.failures) == 1
    assert report.failures[0].workflow_name == "WorkflowB"

    combined_logs = "\n".join(caplog.messages)
    assert "[fan-out error] workflow=WorkflowB tenant=tenant-1 reason=dispatch_failed" in combined_logs
    assert "provider=microsoft_defender" in combined_logs
    assert "event_type=alert" in combined_logs


@pytest.mark.asyncio
async def test_unknown_route_key_returns_empty_dispatch_report() -> None:
    registry = RouteRegistry()
    dispatcher = _DispatchSpy()
    intent = WorkflowIntent(
        tenant_id="tenant-1",
        provider="unknown_provider",
        event_type="unknown_event",
        intent_type="unknown",
    )

    report = await registry.dispatch_best_effort(intent, dispatcher)
    assert report.attempted == 0
    assert report.succeeded == 0
    assert report.failed == 0
    assert dispatcher.calls == []
