"""End-to-end ingress intent fan-out verification.

Responsibility: validate raw envelope to canonical intent normalization and best-effort route dispatch start behavior.
This module must not test provider signature verification or workflow internals.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import pytest

from shared.models import CanonicalEvent, RawIngressEnvelope
from shared.models.mappers import to_security_event
from shared.normalization.normalizers import canonical_event_to_workflow_intent
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
async def test_raw_envelope_to_intent_to_fanout_temporal_start(caplog: pytest.LogCaptureFixture) -> None:
    envelope = RawIngressEnvelope(
        request_id="req-1",
        tenant_id="tenant-1",
        provider="microsoft_defender",
        route="/api/v1/ingress/event/tenant-1",
        method="POST",
        headers={},
        received_at=datetime.now(timezone.utc),
        raw_body={
            "alert_id": "a-1",
            "severity": "high",
            "title": "Suspicious sign-in",
            "description": "desc",
            "user_email": "analyst@example.com",
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
        },
    )

    canonical_event = CanonicalEvent(
        event_type="defender.alert",
        tenant_id=envelope.tenant_id,
        provider=envelope.provider,
        external_event_id="a-1",
        subject="Suspicious sign-in",
        severity="high",
        payload=dict(envelope.raw_body),
        request_id=envelope.request_id,
    )
    security_event = to_security_event(canonical_event)
    intent = canonical_event_to_workflow_intent(
        canonical_event,
        workflow_input=security_event.model_dump(mode="json"),
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
        report = await fanout.dispatch_intent(intent)

    assert report.attempted == 2
    assert report.failed == 1
    assert report.succeeded == 1
    assert len(starter.started) == 1
    assert starter.started[0]["workflow_name"] == "WorkflowWillStart"

    log_text = "\n".join(caplog.messages)
    assert "[fan-out error] workflow=WorkflowWillFail tenant=tenant-1 reason=starter_failed" in log_text
