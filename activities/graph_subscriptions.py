from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone

import boto3
from boto3.dynamodb.conditions import Attr
from temporalio import activity

from activities._activity_errors import application_error_from_http_status, raise_activity_error
from shared.graph_client import get_graph_client
from shared.models import GraphSubscriptionConfig, GraphSubscriptionState, TenantSecrets

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
MIN_SUBSCRIPTION_MINUTES = 45
DEFAULT_MAX_SUBSCRIPTION_MINUTES = 4230
RICH_NOTIFICATION_MAX_MINUTES = 1440

GRAPH_SUBSCRIPTIONS_TABLE = os.environ.get("GRAPH_SUBSCRIPTIONS_TABLE", "").strip()
GRAPH_LIFECYCLE_NOTIFICATION_URL = os.environ.get("GRAPH_LIFECYCLE_NOTIFICATION_URL", "").strip()
ssm_client = None
dynamodb = None


def _max_subscription_minutes(resource: str, include_resource_data: bool) -> int:
    if include_resource_data:
        return RICH_NOTIFICATION_MAX_MINUTES

    lowered = resource.lower()
    # Common resources that support up to 72h.
    if any(token in lowered for token in ["/messages", "/events", "/contacts", "/teams", "/chats"]):
        return 4320
    # Security alerts support 30-day subscriptions.
    if "security/alerts" in lowered:
        return 43200
    return DEFAULT_MAX_SUBSCRIPTION_MINUTES


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


def _compute_expiration(hours: int, *, resource: str, include_resource_data: bool) -> datetime:
    requested_minutes = max(MIN_SUBSCRIPTION_MINUTES, int(hours * 60))
    bounded_minutes = min(requested_minutes, _max_subscription_minutes(resource, include_resource_data))
    return _utc_now() + timedelta(minutes=bounded_minutes)


def _normalize_state(data: dict) -> GraphSubscriptionState:
    return GraphSubscriptionState(
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


def _raise_graph_error(
    tenant_id: str,
    action: str,
    status_code: int,
    retry_after: str | None = None,
) -> None:
    retry_after_seconds: int | None = None
    if retry_after:
        try:
            retry_after_seconds = int(retry_after)
        except ValueError:
            retry_after_seconds = None
    raise application_error_from_http_status(
        tenant_id,
        "microsoft_graph",
        action,
        status_code,
        error_type_prefix="GraphSubscriptionError",
        retry_after_seconds=retry_after_seconds,
    )


@activity.defn
async def create_graph_subscription(
    tenant_id: str,
    subscription: GraphSubscriptionConfig,
    secrets: TenantSecrets,
    notification_url: str,
    client_state: str,
) -> GraphSubscriptionState:
    """Create a Graph webhook subscription for a tenant and resource."""
    expiration = _compute_expiration(
        subscription.expiration_hours,
        resource=subscription.resource,
        include_resource_data=subscription.include_resource_data,
    )
    body: dict[str, object] = {
        "changeType": ",".join(subscription.change_types),
        "notificationUrl": notification_url,
        "resource": subscription.resource,
        "expirationDateTime": expiration.isoformat().replace("+00:00", "Z"),
        "clientState": client_state,
    }
    if subscription.include_resource_data:
        cert = (subscription.encryption_certificate or "").strip()
        cert_id = (subscription.encryption_certificate_id or "").strip()
        if cert and cert_id:
            body["includeResourceData"] = True
            body["encryptionCertificate"] = cert
            body["encryptionCertificateId"] = cert_id
        else:
            activity.logger.warning(
                "[%s] include_resource_data requested for %s but encryption metadata is missing; falling back to basic notifications",
                tenant_id,
                subscription.resource,
            )
    lifecycle_url = (subscription.lifecycle_notification_url or GRAPH_LIFECYCLE_NOTIFICATION_URL).strip()
    if lifecycle_url:
        body["lifecycleNotificationUrl"] = lifecycle_url

    async with get_graph_client(secrets) as client:
        response = await client.post(f"{GRAPH_BASE}/subscriptions", json=body)

    if response.status_code not in {200, 201}:
        _raise_graph_error(
            tenant_id,
            "create_graph_subscription",
            response.status_code,
            response.headers.get("Retry-After"),
        )

    payload = response.json()
    state = GraphSubscriptionState(
        subscription_id=str(payload.get("id", "")),
        tenant_id=tenant_id,
        resource=str(payload.get("resource") or subscription.resource),
        change_types=subscription.change_types,
        expires_at=_parse_dt(payload.get("expirationDateTime"), fallback=expiration),
        notification_url=str(payload.get("notificationUrl") or notification_url),
        client_state=str(payload.get("clientState") or client_state),
    )
    await store_subscription_metadata(state)
    return state


@activity.defn
async def renew_graph_subscription(
    tenant_id: str,
    subscription_id: str,
    expiration_hours: int,
    secrets: TenantSecrets,
) -> GraphSubscriptionState:
    """Renew an existing Graph webhook subscription."""
    existing = await lookup_subscription_metadata(subscription_id)
    resource = existing.resource if existing else ""
    expiration = _compute_expiration(
        expiration_hours,
        resource=resource,
        include_resource_data=False,
    )

    async with get_graph_client(secrets) as client:
        response = await client.patch(
            f"{GRAPH_BASE}/subscriptions/{subscription_id}",
            json={"expirationDateTime": expiration.isoformat().replace("+00:00", "Z")},
        )

    if response.status_code != 200:
        _raise_graph_error(
            tenant_id,
            "renew_graph_subscription",
            response.status_code,
            response.headers.get("Retry-After"),
        )

    payload = response.json()
    state = GraphSubscriptionState(
        subscription_id=subscription_id,
        tenant_id=tenant_id,
        resource=str(payload.get("resource") or (existing.resource if existing else "")),
        change_types=existing.change_types if existing else [],
        expires_at=_parse_dt(payload.get("expirationDateTime"), fallback=expiration),
        notification_url=str(payload.get("notificationUrl") or (existing.notification_url if existing else "")),
        client_state=str(payload.get("clientState") or (existing.client_state if existing else "")),
    )
    await store_subscription_metadata(state)
    return state


@activity.defn
async def delete_graph_subscription(tenant_id: str, subscription_id: str, secrets: TenantSecrets) -> bool:
    """Delete a Graph subscription and remove local metadata."""
    async with get_graph_client(secrets) as client:
        response = await client.delete(f"{GRAPH_BASE}/subscriptions/{subscription_id}")

    if response.status_code not in {200, 202, 204, 404}:
        _raise_graph_error(
            tenant_id,
            "delete_graph_subscription",
            response.status_code,
            response.headers.get("Retry-After"),
        )

    if GRAPH_SUBSCRIPTIONS_TABLE:
        try:
            table = _get_dynamodb_resource().Table(GRAPH_SUBSCRIPTIONS_TABLE)
            await asyncio.to_thread(table.delete_item, Key={"subscription_id": subscription_id})
        except Exception as exc:
            activity.logger.warning("Failed to delete subscription metadata from DynamoDB: %s", exc)
    else:
        base = f"/secamo/tenants/{tenant_id}/subscriptions/{subscription_id}/"
        for key in ["id", "resource", "expires_at", "change_types", "notification_url", "client_state"]:
            activity.heartbeat({"stage": "delete_subscription_metadata", "key": key})
            try:
                await asyncio.to_thread(_get_ssm_client().delete_parameter, Name=f"{base}{key}")
            except _get_ssm_client().exceptions.ParameterNotFound:
                continue
            except Exception as exc:
                activity.logger.warning("Failed deleting SSM parameter %s: %s", key, exc)

    return True


@activity.defn
async def list_graph_subscriptions(tenant_id: str, secrets: TenantSecrets) -> list[GraphSubscriptionState]:
    """List active Graph subscriptions for the app and filter by tenant marker."""
    async with get_graph_client(secrets) as client:
        response = await client.get(f"{GRAPH_BASE}/subscriptions")

    if response.status_code != 200:
        _raise_graph_error(
            tenant_id,
            "list_graph_subscriptions",
            response.status_code,
            response.headers.get("Retry-After"),
        )

    states: list[GraphSubscriptionState] = []
    for item in response.json().get("value", []):
        client_state = str(item.get("clientState") or "")
        if client_state and not client_state.startswith(f"secamo:{tenant_id}:"):
            continue
        states.append(
            GraphSubscriptionState(
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
async def store_subscription_metadata(state: GraphSubscriptionState) -> dict[str, str]:
    """Persist tenant/subscription mapping in DynamoDB or SSM fallback."""
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
        if key == "tenant_id" or key == "subscription_id":
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
async def load_subscription_metadata(tenant_id: str) -> list[GraphSubscriptionState]:
    """Load all persisted subscriptions for a tenant."""
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
        activity.heartbeat({"stage": "load_subscription_metadata", "processed": len(grouped)})
        name = str(parameter.get("Name") or "")
        parts = [p for p in name.split("/") if p]
        if len(parts) < 6:
            continue
        sub_id = parts[-2]
        key = parts[-1]
        grouped.setdefault(sub_id, {})[key] = parameter.get("Value")

    results: list[GraphSubscriptionState] = []
    for sub_id, values in grouped.items():
        results.append(
            GraphSubscriptionState(
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
async def lookup_subscription_metadata(subscription_id: str) -> GraphSubscriptionState | None:
    """Resolve a subscription ID to tenant metadata for routing."""
    if GRAPH_SUBSCRIPTIONS_TABLE:
        table = _get_dynamodb_resource().Table(GRAPH_SUBSCRIPTIONS_TABLE)
        response = await asyncio.to_thread(table.get_item, Key={"subscription_id": subscription_id})
        item = response.get("Item")
        return _normalize_state(item) if item else None

    # SSM fallback performs a bounded scan by active tenants.
    return None
