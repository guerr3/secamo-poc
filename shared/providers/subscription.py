from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone
from typing import Any, cast

import boto3
from boto3.dynamodb.conditions import Attr

from shared.models.subscriptions import SubscriptionConfig, SubscriptionState
from shared.providers.protocols import ConnectorInterface


GRAPH_SUBSCRIPTIONS_TABLE = os.environ.get("GRAPH_SUBSCRIPTIONS_TABLE", "").strip()


class ConnectorSubscriptionProvider:
    """Subscription provider backed by connector actions and AWS metadata storage."""

    _ssm_client = None
    _dynamodb_resource = None

    def __init__(
        self,
        *,
        tenant_id: str,
        connector: ConnectorInterface,
    ) -> None:
        self._tenant_id = tenant_id
        self._connector = connector

    @classmethod
    def _get_ssm_client(cls):
        if cls._ssm_client is None:
            cls._ssm_client = boto3.client("ssm", region_name="eu-west-1")
        return cls._ssm_client

    @classmethod
    def _get_dynamodb_resource(cls):
        if cls._dynamodb_resource is None:
            cls._dynamodb_resource = boto3.resource("dynamodb", region_name="eu-west-1")
        return cls._dynamodb_resource

    @staticmethod
    def _utc_now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _parse_dt(value: str | datetime | None, fallback: datetime) -> datetime:
        if isinstance(value, datetime):
            return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if isinstance(value, str) and value:
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                return parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                return fallback
        return fallback

    @staticmethod
    def _max_subscription_minutes(resource: str, include_resource_data: bool) -> int:
        if include_resource_data:
            return 1440
        lowered = resource.lower()
        if any(token in lowered for token in ["/messages", "/events", "/contacts", "/teams", "/chats"]):
            return 4320
        if "security/alerts" in lowered:
            return 43200
        return 4230

    @classmethod
    def _compute_expiration(
        cls,
        hours: int,
        *,
        resource: str,
        include_resource_data: bool,
    ) -> datetime:
        requested_minutes = max(45, int(hours * 60))
        bounded_minutes = min(requested_minutes, cls._max_subscription_minutes(resource, include_resource_data))
        return cls._utc_now() + timedelta(minutes=bounded_minutes)

    @classmethod
    def _normalize_state(cls, data: dict[str, Any]) -> SubscriptionState:
        return SubscriptionState(
            subscription_id=str(data.get("subscription_id") or data.get("id") or ""),
            tenant_id=str(data.get("tenant_id") or ""),
            resource=str(data.get("resource") or ""),
            change_types=list(data.get("change_types") or []),
            expires_at=cls._parse_dt(
                data.get("expires_at") or data.get("expirationDateTime"),
                fallback=cls._utc_now() + timedelta(hours=1),
            ),
            notification_url=str(data.get("notification_url") or data.get("notificationUrl") or ""),
            client_state=str(data.get("client_state") or data.get("clientState") or ""),
        )

    async def store_metadata(self, state: SubscriptionState) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "subscription_id": state.subscription_id,
            "tenant_id": state.tenant_id,
            "resource": state.resource,
            "change_types": state.change_types,
            "expires_at": state.expires_at.isoformat().replace("+00:00", "Z"),
            "notification_url": state.notification_url,
            "client_state": state.client_state,
        }

        if GRAPH_SUBSCRIPTIONS_TABLE:
            table = cast(Any, self._get_dynamodb_resource()).Table(GRAPH_SUBSCRIPTIONS_TABLE)
            await asyncio.to_thread(table.put_item, Item=payload)
            return payload

        base = f"/secamo/tenants/{state.tenant_id}/subscriptions/{state.subscription_id}/"
        for key, value in payload.items():
            if key in {"tenant_id", "subscription_id"}:
                continue
            as_string = ",".join(value) if isinstance(value, list) else str(value)
            await asyncio.to_thread(
                self._get_ssm_client().put_parameter,
                Name=f"{base}{key}",
                Value=as_string,
                Type="String",
                Overwrite=True,
            )

        await asyncio.to_thread(
            self._get_ssm_client().put_parameter,
            Name=f"{base}id",
            Value=state.subscription_id,
            Type="String",
            Overwrite=True,
        )
        return payload

    async def load_metadata(self, tenant_id: str) -> list[SubscriptionState]:
        if GRAPH_SUBSCRIPTIONS_TABLE:
            table = cast(Any, self._get_dynamodb_resource()).Table(GRAPH_SUBSCRIPTIONS_TABLE)
            response = await asyncio.to_thread(table.scan, FilterExpression=Attr("tenant_id").eq(tenant_id))
            return [self._normalize_state(item) for item in response.get("Items", [])]

        path = f"/secamo/tenants/{tenant_id}/subscriptions/"
        response = await asyncio.to_thread(
            self._get_ssm_client().get_parameters_by_path,
            Path=path,
            WithDecryption=False,
            Recursive=True,
        )
        grouped: dict[str, dict[str, Any]] = {}
        for parameter in response.get("Parameters", []):
            name = str(parameter.get("Name") or "")
            parts = [part for part in name.split("/") if part]
            if len(parts) < 6:
                continue
            sub_id = parts[-2]
            key = parts[-1]
            grouped.setdefault(sub_id, {})[key] = parameter.get("Value")

        results: list[SubscriptionState] = []
        for sub_id, values in grouped.items():
            results.append(
                SubscriptionState(
                    subscription_id=str(values.get("id") or sub_id),
                    tenant_id=tenant_id,
                    resource=str(values.get("resource") or ""),
                    change_types=[
                        item.strip()
                        for item in str(values.get("change_types") or "").split(",")
                        if item.strip()
                    ],
                    expires_at=self._parse_dt(values.get("expires_at"), fallback=self._utc_now() + timedelta(hours=1)),
                    notification_url=str(values.get("notification_url") or ""),
                    client_state=str(values.get("client_state") or ""),
                )
            )
        return results

    async def lookup_metadata(self, subscription_id: str) -> SubscriptionState | None:
        if not GRAPH_SUBSCRIPTIONS_TABLE:
            return None

        table = cast(Any, self._get_dynamodb_resource()).Table(GRAPH_SUBSCRIPTIONS_TABLE)
        response = await asyncio.to_thread(table.get_item, Key={"subscription_id": subscription_id})
        item = response.get("Item")
        return self._normalize_state(item) if item else None

    async def _delete_metadata(self, subscription_id: str) -> None:
        if not GRAPH_SUBSCRIPTIONS_TABLE:
            return
        table = cast(Any, self._get_dynamodb_resource()).Table(GRAPH_SUBSCRIPTIONS_TABLE)
        await asyncio.to_thread(table.delete_item, Key={"subscription_id": subscription_id})

    async def create_subscription(
        self,
        subscription: SubscriptionConfig,
        *,
        secret_type: str,
        notification_url: str,
        client_state: str,
    ) -> SubscriptionState:
        expiration = self._compute_expiration(
            subscription.expiration_hours,
            resource=subscription.resource,
            include_resource_data=subscription.include_resource_data,
        )
        payload: dict[str, Any] = {
            "resource": subscription.resource,
            "change_types": subscription.change_types,
            "notification_url": notification_url,
            "client_state": client_state,
            "expiration_minutes": max(45, int(subscription.expiration_hours * 60)),
            "secret_type": secret_type or "graph",
            "include_resource_data": subscription.include_resource_data,
        }

        cert = (subscription.encryption_certificate or "").strip()
        cert_id = (subscription.encryption_certificate_id or "").strip()
        if cert and cert_id:
            payload["encryption_certificate"] = cert
            payload["encryption_certificate_id"] = cert_id

        lifecycle_url = (subscription.lifecycle_notification_url or "").strip()
        if lifecycle_url:
            payload["lifecycle_notification_url"] = lifecycle_url

        response = await self._connector.execute_action("create_subscription", payload)
        response_payload = response if isinstance(response, dict) else {}
        state = SubscriptionState(
            subscription_id=str(response_payload.get("id", "")),
            tenant_id=self._tenant_id,
            resource=str(response_payload.get("resource") or subscription.resource),
            change_types=subscription.change_types,
            expires_at=self._parse_dt(response_payload.get("expirationDateTime"), fallback=expiration),
            notification_url=str(response_payload.get("notificationUrl") or notification_url),
            client_state=str(response_payload.get("clientState") or client_state),
        )
        await self.store_metadata(state)
        return state

    async def renew_subscription(
        self,
        subscription_id: str,
        *,
        expiration_hours: int,
        secret_type: str,
    ) -> SubscriptionState:
        existing = await self.lookup_metadata(subscription_id)
        resource = existing.resource if existing else ""
        expiration = self._compute_expiration(expiration_hours, resource=resource, include_resource_data=False)
        response = await self._connector.execute_action(
            "renew_subscription",
            {
                "subscription_id": subscription_id,
                "expiration_minutes": max(45, int(expiration_hours * 60)),
                "secret_type": secret_type or "graph",
            },
        )
        response_payload = response if isinstance(response, dict) else {}
        state = SubscriptionState(
            subscription_id=subscription_id,
            tenant_id=self._tenant_id,
            resource=str(response_payload.get("resource") or (existing.resource if existing else "")),
            change_types=existing.change_types if existing else [],
            expires_at=self._parse_dt(response_payload.get("expirationDateTime"), fallback=expiration),
            notification_url=str(response_payload.get("notificationUrl") or (existing.notification_url if existing else "")),
            client_state=str(response_payload.get("clientState") or (existing.client_state if existing else "")),
        )
        await self.store_metadata(state)
        return state

    async def delete_subscription(
        self,
        subscription_id: str,
        *,
        secret_type: str,
    ) -> bool:
        await self._connector.execute_action(
            "delete_subscription",
            {"subscription_id": subscription_id, "secret_type": secret_type or "graph"},
        )
        try:
            await self._delete_metadata(subscription_id)
        except Exception:
            return True
        return True

    async def list_subscriptions(self, *, secret_type: str) -> list[SubscriptionState]:
        response = await self._connector.execute_action(
            "list_subscriptions",
            {"secret_type": secret_type or "graph"},
        )
        payload = response if isinstance(response, dict) else {}
        subscriptions = payload.get("subscriptions", [])

        states: list[SubscriptionState] = []
        for item in subscriptions:
            client_state = str(item.get("clientState") or "")
            if client_state and not client_state.startswith(f"secamo:{self._tenant_id}:"):
                continue
            states.append(
                SubscriptionState(
                    subscription_id=str(item.get("id") or ""),
                    tenant_id=self._tenant_id,
                    resource=str(item.get("resource") or ""),
                    change_types=[
                        value.strip()
                        for value in str(item.get("changeType", "")).split(",")
                        if value.strip()
                    ],
                    expires_at=self._parse_dt(item.get("expirationDateTime"), fallback=self._utc_now() + timedelta(hours=1)),
                    notification_url=str(item.get("notificationUrl") or ""),
                    client_state=client_state,
                )
            )
        return states


async def lookup_subscription_metadata_record(subscription_id: str) -> SubscriptionState | None:
    """Lookup subscription metadata by id using the configured metadata backend."""
    if not GRAPH_SUBSCRIPTIONS_TABLE:
        return None

    table = cast(Any, ConnectorSubscriptionProvider._get_dynamodb_resource()).Table(GRAPH_SUBSCRIPTIONS_TABLE)
    response = await asyncio.to_thread(table.get_item, Key={"subscription_id": subscription_id})
    item = response.get("Item")
    return ConnectorSubscriptionProvider._normalize_state(item) if item else None
