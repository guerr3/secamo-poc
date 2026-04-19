from __future__ import annotations

from datetime import datetime, timezone

import pytest
from temporalio.exceptions import ApplicationError

from shared.models.canonical import Correlation, Envelope, IamOnboardingEvent, StoragePartition
from shared.normalization.iam.onboarding_event import normalize_iam_onboarding_case
from shared.routing.contracts import WorkflowRoute
from shared.routing.registry import RouteRegistry
from shared.temporal.dispatcher import RouteFanoutDispatcher


def _correlation() -> Correlation:
    return Correlation(
        correlation_id="corr-1",
        causation_id="corr-1",
        request_id="req-1",
        trace_id="trace-1",
        storage_partition=StoragePartition(
            ddb_pk="TENANT#tenant-1",
            ddb_sk="EVENT#iam#onboarding#evt-1",
            s3_bucket="secamo-events-tenant-1",
            s3_key_prefix="raw/iam.onboarding/evt-1",
        ),
    )


def _iam_envelope(*, action: str = "create", user_id: str = "user-123") -> Envelope:
    return Envelope(
        event_id="evt-1",
        tenant_id="tenant-1",
        source_provider="microsoft_graph",
        event_name="iam.onboarding",
        schema_version="1.0.0",
        event_version="1.0.0",
        ocsf_version="1.1.0",
        occurred_at=datetime.now(timezone.utc),
        correlation=_correlation(),
        payload=IamOnboardingEvent(
            event_type="iam.onboarding",
            activity_id=1,
            user_email="alice@example.com",
            action=action,
            user_data={
                "user_id": user_id,
                "company_name": "Secamo",
                "first_name": "Alice",
                "last_name": "Example",
            },
        ),
        metadata={"requester": "manager@example.com"},
    )


def test_normalize_iam_onboarding_case_maps_fields() -> None:
    case_input = normalize_iam_onboarding_case(_iam_envelope())

    assert case_input.tenant_id == "tenant-1"
    assert case_input.action == "create"
    assert case_input.user_id == "user-123"
    assert case_input.user_email == "alice@example.com"
    assert case_input.requester == "manager@example.com"
    assert case_input.user_data["company_name"] == "Secamo"


def test_normalize_iam_onboarding_case_rejects_unknown_action() -> None:
    payload = IamOnboardingEvent(
        event_type="iam.onboarding",
        activity_id=1,
        user_email="alice@example.com",
        action="create",
        user_data={"user_id": "user-123"},
    )
    invalid_payload = payload.model_copy(update={"action": "suspend"})
    envelope = _iam_envelope().model_copy(update={"payload": invalid_payload})

    with pytest.raises(ApplicationError, match="Unsupported iam.onboarding action") as exc:
        normalize_iam_onboarding_case(envelope)

    assert exc.value.non_retryable is True


class _StarterSpy:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def start(
        self,
        *,
        workflow_name: str,
        workflow_input: dict,
        task_queue: str,
        tenant_id: str,
        workflow_id: str,
    ) -> dict:
        self.calls.append(
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
async def test_route_fanout_dispatcher_normalizes_iam_workflow_input() -> None:
    registry = RouteRegistry()
    registry.register(
        "microsoft_graph",
        "iam.onboarding",
        (WorkflowRoute(workflow_name="IamOnboardingWorkflow", task_queue="user-lifecycle"),),
    )

    starter = _StarterSpy()
    dispatcher = RouteFanoutDispatcher(registry, starter)

    report = await dispatcher.dispatch_intent(_iam_envelope())

    assert report.attempted == 1
    assert report.succeeded == 1
    assert len(starter.calls) == 1

    started_input = starter.calls[0]["workflow_input"]
    assert started_input == {
        "tenant_id": "tenant-1",
        "action": "create",
        "user_id": "user-123",
        "user_email": "alice@example.com",
        "requester": "manager@example.com",
        "user_data": {
            "user_id": "user-123",
            "company_name": "Secamo",
            "first_name": "Alice",
            "last_name": "Example",
        },
    }
