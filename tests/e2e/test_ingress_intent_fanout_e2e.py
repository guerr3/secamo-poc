"""End-to-end ingress intent fan-out verification.

Responsibility: validate envelope fan-out normalization and best-effort route dispatch start behavior.
This module must not test provider signature verification or workflow internals.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import pytest

from shared.models.canonical import Correlation, DefenderDetectionFindingEvent, Envelope, StoragePartition
from shared.routing.contracts import WorkflowRoute
from shared.routing.registry import RouteRegistry
from shared.temporal.dispatcher import RouteFanoutDispatcher


class _FakeStarter:
    def __init__(self, fail_workflow_name: str | None = None) -> None:
        self.fail_workflow_name = fail_workflow_name
        self.started: list[dict] = []

    async def start(self, *, workflow_name: str, workflow_input: dict, task_queue: str, tenant_id: str, workflow_id: str):
        if self.fail_workflow_name and workflow_name == self.fail_workflow_name:
            raise RuntimeError("starter_failed")
        self.started.append(
            {
                "workflow_name": workflow_name,
                "workflow_input": workflow_input,
                "task_queue": task_queue,
                "tenant_id": tenant_id,
                "workflow_id": workflow_id,
            }
        )
        return {"ok": True}


@pytest.mark.asyncio
async def test_envelope_to_fanout_temporal_start(caplog: pytest.LogCaptureFixture) -> None:
    envelope = Envelope(
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
            description="desc",
            severity_id=60,
            severity="high",
        ),
    )

    logger = logging.getLogger("tests.e2e.fanout")
    registry = RouteRegistry(logger=logger)
    registry.register(
        "microsoft_defender",
        "defender.alert",
        (
            WorkflowRoute(workflow_name="WorkflowWillFail", task_queue="soc-defender"),
            WorkflowRoute(workflow_name="WorkflowWillStart", task_queue="soc-defender"),
        ),
    )

    starter = _FakeStarter(fail_workflow_name="WorkflowWillFail")
    fanout = RouteFanoutDispatcher(registry, starter)

    with caplog.at_level(logging.ERROR):
        report = await fanout.dispatch_intent(envelope)

    assert report.attempted == 2
    assert report.failed == 1
    assert report.succeeded == 1
    assert len(starter.started) == 1
    assert starter.started[0]["workflow_name"] == "WorkflowWillStart"

    log_text = "\n".join(caplog.messages)
    assert "[fan-out error] workflow=WorkflowWillFail tenant=tenant-1 reason=starter_failed" in log_text
