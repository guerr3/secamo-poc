from __future__ import annotations

import os
from dataclasses import dataclass

import boto3

from shared.models import GraphNotificationEnvelope, GraphNotificationItem

GRAPH_SUBSCRIPTIONS_TABLE = os.environ.get("GRAPH_SUBSCRIPTIONS_TABLE", "").strip()


@dataclass(frozen=True)
class ResolvedNotification:
    tenant_id: str
    item: GraphNotificationItem


class GraphIngressValidator:
    """Validate Graph webhook notifications and resolve tenant context."""

    def __init__(self) -> None:
        self._ddb = None

    def _get_dynamodb(self):
        if self._ddb is None:
            self._ddb = boto3.resource("dynamodb", region_name="eu-west-1")
        return self._ddb

    def resolve_tenant_id(self, item: GraphNotificationItem) -> str | None:
        client_state = str(item.clientState or "")
        if client_state.startswith("secamo:"):
            parts = client_state.split(":", 2)
            if len(parts) >= 3:
                return parts[1]

        if not GRAPH_SUBSCRIPTIONS_TABLE:
            return None

        table = self._get_dynamodb().Table(GRAPH_SUBSCRIPTIONS_TABLE)
        response = table.get_item(Key={"subscription_id": item.subscriptionId})
        metadata = response.get("Item")
        if not metadata:
            return None

        expected_client_state = str(metadata.get("client_state") or "")
        if expected_client_state and client_state and expected_client_state != client_state:
            return None

        return str(metadata.get("tenant_id") or "") or None

    def validate_and_resolve(
        self,
        envelope: GraphNotificationEnvelope,
    ) -> list[ResolvedNotification]:
        resolved: list[ResolvedNotification] = []
        for item in envelope.value:
            tenant_id = self.resolve_tenant_id(item)
            if not tenant_id:
                continue
            resolved.append(ResolvedNotification(tenant_id=tenant_id, item=item))
        return resolved
