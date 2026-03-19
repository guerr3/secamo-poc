from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from temporalio.client import Client
from temporalio.contrib.pydantic import pydantic_data_converter

from shared.config import QUEUE_SOC, TEMPORAL_ADDRESS, TEMPORAL_NAMESPACE
from shared.models import GraphNotificationEnvelope, GraphNotificationItem, RawIngressEnvelope


class TemporalGraphIngressDispatcher:
    """Dispatch validated Graph notifications into Temporal for routing."""

    def __init__(self) -> None:
        self._client: Client | None = None

    async def _get_client(self) -> Client:
        if self._client is None:
            self._client = await Client.connect(
                TEMPORAL_ADDRESS,
                namespace=TEMPORAL_NAMESPACE,
                data_converter=pydantic_data_converter,
            )
        return self._client

    async def dispatch(self, tenant_id: str, notifications: list[GraphNotificationItem]) -> str:
        client = await self._get_client()
        request_id = str(uuid4())
        envelope = RawIngressEnvelope(
            request_id=request_id,
            tenant_id=tenant_id,
            provider="microsoft_graph",
            route="graph/notifications",
            method="POST",
            headers={},
            received_at=datetime.now(timezone.utc),
            raw_body=GraphNotificationEnvelope(value=notifications).model_dump(mode="json"),
        )

        workflow_id = f"graph-ingress-router-{tenant_id}-{request_id}"
        await client.start_workflow(
            "GraphIngressRouterWorkflow",
            envelope,
            id=workflow_id,
            task_queue=QUEUE_SOC,
        )
        return workflow_id
