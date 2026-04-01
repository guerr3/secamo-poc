"""Graph subscription management activities.

These remain Graph-specific since they are tightly coupled to
Microsoft Graph subscription semantics.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone

import boto3
from boto3.dynamodb.conditions import Attr
from temporalio import activity

from activities.provider_capabilities import connector_execute_action
from shared.models.subscriptions import SubscriptionConfig, SubscriptionState

GRAPH_SUBSCRIPTIONS_TABLE = os.environ.get("GRAPH_SUBSCRIPTIONS_TABLE", "").strip()
ssm_client = None
dynamodb = None


def _get_ssm_client():
    global ssm_client
    if ssm_client is None:
        ssm_client = boto3.client("ssm", region_name="eu-west-1")
    return ssm_client


def _get_dynamodb_resource():
    global dynamodb
    if dynamodb is None:
        dynamodb = boto3.resource("dynamodb", region_name="eu-west-1")
    return dynamodb


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


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


def _max_subscription_minutes(resource: str, include_resource_data: bool) -> int:
    if include_resource_data:
        return 1440
    lowered = resource.lower()
    if any(token in lowered for token in ["/messages", "/events", "/contacts", "/teams", "/chats"]):
        return 4320
    if "security/alerts" in lowered:
        return 43200
    return 4230


def _compute_expiration(hours: int, *, resource: str, include_resource_data: bool) -> datetime:
    requested_minutes = max(45, int(hours * 60))
    bounded_minutes = min(requested_minutes, _max_subscription_minutes(resource, include_resource_data))
    return _utc_now() + timedelta(minutes=bounded_minutes)


def _normalize_state(data: dict) -> SubscriptionState:
    return SubscriptionState(
        subscription_id=str(data.get("subscription_id") or data.get("id") or ""),
        tenant_id=str(data.get("tenant_id") or ""),
        resource=str(data.get("resource") or ""),
        change_types=list(data.get("change_types") or []),
        expires_at=_parse_dt(
            data.get("expires_at") or data.get("expirationDateTime"),
            fallback=_utc_now() + timedelta(hours=1),
        ),
        notification_url=str(data.get("notification_url") or data.get("notificationUrl") or ""),
        client_state=str(data.get("client_state") or data.get("clientState") or ""),
    )


# ── Internal metadata persistence ────────────────────────────


@activity.defn
async def store_subscription_metadata(state: SubscriptionState) -> dict[str, str]:
    payload = {
        "subscription_id": state.subscription_id,
        "tenant_id": state.tenant_id,
        "resource": state.resource,
        "change_types": state.change_types,
        "expires_at": state.expires_at.isoformat().replace("+00:00", "Z"),
        "notification_url": state.notification_url,
        "client_state": state.client_state,
    }

    if GRAPH_SUBSCRIPTIONS_TABLE:
        table = _get_dynamodb_resource().Table(GRAPH_SUBSCRIPTIONS_TABLE)
        await asyncio.to_thread(table.put_item, Item=payload)
        return payload

    base = f"/secamo/tenants/{state.tenant_id}/subscriptions/{state.subscription_id}/"
    for key, value in payload.items():
        if key in {"tenant_id", "subscription_id"}:
            continue
        as_string = ",".join(value) if isinstance(value, list) else str(value)
        await asyncio.to_thread(
            _get_ssm_client().put_parameter,
            Name=f"{base}{key}",
            Value=as_string,
            Type="String",
            Overwrite=True,
        )
    await asyncio.to_thread(
        _get_ssm_client().put_parameter,
        Name=f"{base}id",
        Value=state.subscription_id,
        Type="String",
        Overwrite=True,
    )
    return payload


@activity.defn
async def load_subscription_metadata(tenant_id: str) -> list[SubscriptionState]:
    if GRAPH_SUBSCRIPTIONS_TABLE:
        table = _get_dynamodb_resource().Table(GRAPH_SUBSCRIPTIONS_TABLE)
        response = await asyncio.to_thread(table.scan, FilterExpression=Attr("tenant_id").eq(tenant_id))
        return [_normalize_state(item) for item in response.get("Items", [])]

    path = f"/secamo/tenants/{tenant_id}/subscriptions/"
    response = await asyncio.to_thread(
        _get_ssm_client().get_parameters_by_path,
        Path=path,
        WithDecryption=False,
        Recursive=True,
    )
    grouped: dict[str, dict] = {}
    for parameter in response.get("Parameters", []):
        name = str(parameter.get("Name") or "")
        parts = [p for p in name.split("/") if p]
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
                change_types=[x.strip() for x in str(values.get("change_types") or "").split(",") if x.strip()],
                expires_at=_parse_dt(values.get("expires_at"), fallback=_utc_now() + timedelta(hours=1)),
                notification_url=str(values.get("notification_url") or ""),
                client_state=str(values.get("client_state") or ""),
            )
        )
    return results


@activity.defn
async def lookup_subscription_metadata(subscription_id: str) -> SubscriptionState | None:
    if GRAPH_SUBSCRIPTIONS_TABLE:
        table = _get_dynamodb_resource().Table(GRAPH_SUBSCRIPTIONS_TABLE)
        response = await asyncio.to_thread(table.get_item, Key={"subscription_id": subscription_id})
        item = response.get("Item")
        return _normalize_state(item) if item else None
    return None


# ── Subscription lifecycle activities ────────────────────────


@activity.defn
async def subscription_create(
    tenant_id: str,
    subscription: SubscriptionConfig,
    secret_type: str,
    notification_url: str,
    client_state: str,
) -> SubscriptionState:
    expiration = _compute_expiration(
        subscription.expiration_hours,
        resource=subscription.resource,
        include_resource_data=subscription.include_resource_data,
    )
    payload: dict[str, object] = {
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

    action_result = await connector_execute_action(
        tenant_id,
        "microsoft_defender",
        "create_subscription",
        payload,
    )
    response_payload = action_result.data.payload
    state = SubscriptionState(
        subscription_id=str(response_payload.get("id", "")),
        tenant_id=tenant_id,
        resource=str(response_payload.get("resource") or subscription.resource),
        change_types=subscription.change_types,
        expires_at=_parse_dt(response_payload.get("expirationDateTime"), fallback=expiration),
        notification_url=str(response_payload.get("notificationUrl") or notification_url),
        client_state=str(response_payload.get("clientState") or client_state),
    )
    await store_subscription_metadata(state)
    return state


@activity.defn
async def subscription_renew(
    tenant_id: str,
    subscription_id: str,
    expiration_hours: int,
    secret_type: str,
) -> SubscriptionState:
    existing = await lookup_subscription_metadata(subscription_id)
    resource = existing.resource if existing else ""
    expiration = _compute_expiration(expiration_hours, resource=resource, include_resource_data=False)
    action_result = await connector_execute_action(
        tenant_id,
        "microsoft_defender",
        "renew_subscription",
        {
            "subscription_id": subscription_id,
            "expiration_minutes": max(45, int(expiration_hours * 60)),
            "secret_type": secret_type or "graph",
        },
    )
    response_payload = action_result.data.payload
    state = SubscriptionState(
        subscription_id=subscription_id,
        tenant_id=tenant_id,
        resource=str(response_payload.get("resource") or (existing.resource if existing else "")),
        change_types=existing.change_types if existing else [],
        expires_at=_parse_dt(response_payload.get("expirationDateTime"), fallback=expiration),
        notification_url=str(
            response_payload.get("notificationUrl") or (existing.notification_url if existing else "")
        ),
        client_state=str(response_payload.get("clientState") or (existing.client_state if existing else "")),
    )
    await store_subscription_metadata(state)
    return state


@activity.defn
async def subscription_delete(tenant_id: str, subscription_id: str, secret_type: str) -> bool:
    await connector_execute_action(
        tenant_id,
        "microsoft_defender",
        "delete_subscription",
        {"subscription_id": subscription_id, "secret_type": secret_type or "graph"},
    )
    if GRAPH_SUBSCRIPTIONS_TABLE:
        try:
            table = _get_dynamodb_resource().Table(GRAPH_SUBSCRIPTIONS_TABLE)
            await asyncio.to_thread(table.delete_item, Key={"subscription_id": subscription_id})
        except Exception as exc:
            activity.logger.warning("Failed to delete subscription metadata from DynamoDB: %s", exc)
    else:
        return True
    return True


@activity.defn
async def subscription_list(tenant_id: str, secret_type: str) -> list[SubscriptionState]:
    action_result = await connector_execute_action(
        tenant_id,
        "microsoft_defender",
        "list_subscriptions",
        {"secret_type": secret_type or "graph"},
    )
    subscriptions = action_result.data.payload.get("subscriptions", [])
    states: list[SubscriptionState] = []
    for item in subscriptions:
        client_state = str(item.get("clientState") or "")
        if client_state and not client_state.startswith(f"secamo:{tenant_id}:"):
            continue
        states.append(
            SubscriptionState(
                subscription_id=str(item.get("id") or ""),
                tenant_id=tenant_id,
                resource=str(item.get("resource") or ""),
                change_types=[x.strip() for x in str(item.get("changeType", "")).split(",") if x.strip()],
                expires_at=_parse_dt(item.get("expirationDateTime"), fallback=_utc_now() + timedelta(hours=1)),
                notification_url=str(item.get("notificationUrl") or ""),
                client_state=client_state,
            )
        )
    return states


@activity.defn
async def subscription_metadata_store(state: SubscriptionState) -> dict[str, str]:
    return await store_subscription_metadata(state)


@activity.defn
async def subscription_metadata_load(tenant_id: str) -> list[SubscriptionState]:
    return await load_subscription_metadata(tenant_id)


@activity.defn
async def subscription_metadata_lookup(subscription_id: str) -> SubscriptionState | None:
    return await lookup_subscription_metadata(subscription_id)
