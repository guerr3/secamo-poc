"""Graph ingress Temporal dispatch adapter.

Responsibility: convert validated Graph notifications to canonical events and dispatch them via shared intent/routing boundaries.
This module must not contain provider authentication logic or API transport endpoint handlers.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from temporalio.client import Client
from temporalio.contrib.pydantic import pydantic_data_converter

from shared.config import TEMPORAL_ADDRESS, TEMPORAL_NAMESPACE
from shared.models import CanonicalEvent, GraphNotificationItem
from shared.models.mappers import to_security_event
from shared.normalization.normalizers import canonical_event_to_workflow_intent
from shared.routing import build_default_route_registry
from shared.temporal.dispatcher import RouteFanoutDispatcher, WorkflowStarter


class _TemporalWorkflowStarter(WorkflowStarter):
    """Temporal workflow starter adapter for route fan-out dispatch."""

    def __init__(self, client: Client) -> None:
        self._client = client

    async def start(
        self,
        *,
        workflow_name: str,
        workflow_input: dict[str, Any],
        task_queue: str,
        tenant_id: str,
        workflow_id: str,
    ) -> Any:
        return await self._client.start_workflow(
            workflow_name,
            workflow_input,
            id=workflow_id,
            task_queue=task_queue,
        )


class TemporalGraphIngressDispatcher:
    """Dispatch validated Graph notifications directly via shared intent routing boundaries."""

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

    @staticmethod
    def _item_to_canonical(tenant_id: str, item: GraphNotificationItem, request_id: str) -> CanonicalEvent | None:
        resource = str(item.resource or "").strip().lower()
        resource_data = item.resourceData or {}

        event_type = ""
        if "alerts" in resource:
            event_type = "defender.alert"
        elif "signin" in resource or "risky" in resource:
            event_type = "defender.impossible_travel"
        if not event_type:
            return None

        alert_id = str(resource_data.get("id") or item.subscriptionId or request_id)
        canonical_payload = {
            "alert_id": alert_id,
            "severity": str(resource_data.get("severity") or "medium").lower(),
            "title": str(resource_data.get("title") or resource_data.get("riskEventType") or "Graph notification"),
            "description": str(resource_data.get("description") or resource_data.get("riskDetail") or ""),
            "device_id": resource_data.get("deviceId") or resource_data.get("azureAdDeviceId"),
            "user_email": resource_data.get("userPrincipalName") or resource_data.get("accountName"),
            "source_ip": resource_data.get("ipAddress"),
            "destination_ip": resource_data.get("destinationIp") or resource_data.get("ipAddress"),
            "resource": item.resource,
            "change_type": item.changeType,
            "subscription_id": item.subscriptionId,
        }

        return CanonicalEvent(
            event_type=event_type,
            tenant_id=tenant_id,
            provider="microsoft_graph",
            external_event_id=alert_id,
            subject=str(canonical_payload["title"]),
            severity=str(canonical_payload["severity"]),
            occurred_at=datetime.now(timezone.utc),
            payload=canonical_payload,
            request_id=request_id,
        )

    async def dispatch(self, tenant_id: str, notifications: list[GraphNotificationItem]) -> str:
        client = await self._get_client()
        starter = _TemporalWorkflowStarter(client)
        fanout = RouteFanoutDispatcher(build_default_route_registry(), starter)

        dispatched = 0
        request_id = str(uuid4())
        for item in notifications:
            canonical_event = self._item_to_canonical(tenant_id, item, request_id)
            if canonical_event is None:
                continue
            security_event = to_security_event(canonical_event)
            intent = canonical_event_to_workflow_intent(
                canonical_event,
                workflow_input=security_event.model_dump(mode="json"),
            )
            report = await fanout.dispatch_intent(intent)
            dispatched += report.succeeded

        return f"dispatched={dispatched}"
