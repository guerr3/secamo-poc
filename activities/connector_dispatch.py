from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone

import boto3
from boto3.dynamodb.conditions import Attr
from pydantic import BaseModel, ConfigDict
from temporalio import activity
from temporalio.exceptions import ApplicationError

from activities._tenant_secrets import load_tenant_secrets
from connectors.errors import ConnectorConfigurationError, ConnectorPermanentError, ConnectorTransientError
from connectors.registry import get_connector
from shared.models import (
    ConnectorActionData,
    ConnectorActionResult,
    ConnectorFetchData,
    ConnectorFetchResult,
    ConnectorHealthData,
    ConnectorHealthResult,
    DefenderDetectionFindingEvent,
    DeviceContext,
    EnrichedAlert,
    IdentityRiskContext,
    ThreatIntelResult,
)
from shared.models.subscriptions import SubscriptionConfig, SubscriptionState
from shared.providers.contracts import TenantSecrets


GRAPH_SUBSCRIPTIONS_TABLE = os.environ.get("GRAPH_SUBSCRIPTIONS_TABLE", "").strip()
ssm_client = None
dynamodb = None


class GraphRiskyUser(BaseModel):
    model_config = ConfigDict(from_attributes=True, frozen=True)

    id: str
    isDeleted: bool | None = None
    isProcessing: bool | None = None
    riskLastUpdatedDateTime: str | None = None
    riskLevel: str | None = None
    riskState: str | None = None
    riskDetail: str | None = None
    userDisplayName: str | None = None
    userPrincipalName: str | None = None


def _to_risky_user_result(payload: dict) -> GraphRiskyUser:
    return GraphRiskyUser(
        id=str(payload.get("id") or ""),
        isDeleted=payload.get("isDeleted") if "isDeleted" in payload else payload.get("is_deleted"),
        isProcessing=payload.get("isProcessing") if "isProcessing" in payload else payload.get("is_processing"),
        riskLastUpdatedDateTime=payload.get("riskLastUpdatedDateTime")
        if "riskLastUpdatedDateTime" in payload
        else payload.get("risk_last_updated_datetime"),
        riskLevel=payload.get("riskLevel") if "riskLevel" in payload else payload.get("risk_level"),
        riskState=payload.get("riskState") if "riskState" in payload else payload.get("risk_state"),
        riskDetail=payload.get("riskDetail") if "riskDetail" in payload else payload.get("risk_detail"),
        userDisplayName=payload.get("userDisplayName") if "userDisplayName" in payload else payload.get("user_display_name"),
        userPrincipalName=payload.get("userPrincipalName")
        if "userPrincipalName" in payload
        else payload.get("user_principal_name"),
    )


def _vendor_value(alert: DefenderDetectionFindingEvent, key: str) -> str | None:
    ext = alert.vendor_extensions.get(key)
    if ext is None or ext.value is None:
        return None
    value = str(ext.value).strip()
    return value or None


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


def _secret_type_for_provider(provider: str) -> str:
    normalized = provider.strip().lower()
    if normalized in {"microsoft_defender", "crowdstrike", "sentinelone", "defender", "microsoft_graph"}:
        return "graph"
    if normalized in {"jira", "halo_itsm", "servicenow"}:
        return "ticketing"
    if normalized in {"virustotal", "abuseipdb", "misp"}:
        return "threatintel"
    raise ConnectorConfigurationError(f"No secret type mapping defined for provider '{provider}'")


def _load_connector_secrets(tenant_id: str, provider: str) -> TenantSecrets:
    secret_type = _secret_type_for_provider(provider)
    return load_tenant_secrets(tenant_id, secret_type)


def _raise_connector_activity_error(operation: str, provider: str, error: Exception) -> None:
    """Translate connector errors into explicit Temporal retry semantics."""
    message = f"connector {operation} failed for provider '{provider}': {error}"

    if isinstance(error, ConnectorPermanentError):
        raise ApplicationError(
            message,
            type="ConnectorPermanentError",
            non_retryable=True,
        ) from error

    if isinstance(error, ConnectorTransientError):
        raise ApplicationError(
            message,
            type="ConnectorTransientError",
            non_retryable=False,
        ) from error

    raise ApplicationError(
        message,
        type="ConnectorActivityError",
        non_retryable=False,
    ) from error


@activity.defn
async def connector_fetch_events(
    tenant_id: str,
    provider: str,
    query: dict,
) -> ConnectorFetchResult:
    activity.logger.info("[%s] Connector fetch events via provider '%s'", tenant_id, provider)
    try:
        secrets = _load_connector_secrets(tenant_id, provider)
        connector = get_connector(provider=provider, tenant_id=tenant_id, secrets=secrets)
        events = await connector.fetch_events(query)
        return ConnectorFetchResult(
            provider=provider,
            success=True,
            details="fetch completed",
            data=ConnectorFetchData(events=events, raw_count=len(events)),
        )
    except Exception as exc:
        activity.logger.exception(
            "[%s] Connector fetch events failed for provider '%s'",
            tenant_id,
            provider,
        )
        _raise_connector_activity_error("fetch_events", provider, exc)


@activity.defn
async def connector_execute_action(
    tenant_id: str,
    provider: str,
    action: str,
    payload: dict,
) -> ConnectorActionResult:
    activity.logger.info("[%s] Connector action '%s' via provider '%s'", tenant_id, action, provider)
    try:
        secrets = _load_connector_secrets(tenant_id, provider)
        connector = get_connector(provider=provider, tenant_id=tenant_id, secrets=secrets)
        data = await connector.execute_action(action=action, payload=payload)

        success = not (isinstance(data, dict) and data.get("success") is False)
        details = "action completed"
        if isinstance(data, dict):
            details = str(data.get("details") or data.get("reason") or details)

        if not success:
            retryable = bool(isinstance(data, dict) and data.get("retryable") is True)
            raise ApplicationError(
                f"connector action '{action}' reported failure for provider '{provider}': {details}",
                type="ConnectorActionReportedFailure",
                non_retryable=not retryable,
            )

        return ConnectorActionResult(
            provider=provider,
            operation_type="action",
            success=True,
            details=details,
            data=ConnectorActionData(action=action, payload=data if isinstance(data, dict) else {}),
        )
    except ApplicationError:
        raise
    except Exception as exc:
        activity.logger.exception(
            "[%s] Connector action '%s' failed for provider '%s'",
            tenant_id,
            action,
            provider,
        )
        _raise_connector_activity_error("execute_action", provider, exc)


@activity.defn
async def connector_health_check(
    tenant_id: str,
    provider: str,
) -> ConnectorHealthResult:
    activity.logger.info("[%s] Connector health check via provider '%s'", tenant_id, provider)
    try:
        secrets = _load_connector_secrets(tenant_id, provider)
        connector = get_connector(provider=provider, tenant_id=tenant_id, secrets=secrets)
        result = await connector.health_check()
        return ConnectorHealthResult(
            provider=provider,
            success=bool(result.get("healthy", False)),
            details=str(result),
            data=ConnectorHealthData(healthy=bool(result.get("healthy", False))),
        )
    except Exception as exc:
        activity.logger.exception(
            "[%s] Connector health check failed for provider '%s'",
            tenant_id,
            provider,
        )
        _raise_connector_activity_error("health_check", provider, exc)


@activity.defn
async def connector_threat_intel_fanout(
    tenant_id: str,
    providers: list[str],
    indicator: str,
) -> ThreatIntelResult:
    """Fan-out TI lookups; return the strongest malicious score."""
    activity.logger.info(
        "[%s] Threat-intel fanout for indicator '%s' across %s",
        tenant_id,
        indicator,
        providers,
    )

    best = ThreatIntelResult(
        indicator=indicator,
        is_malicious=False,
        provider="none",
        reputation_score=0.0,
        details="No provider returned a positive result.",
    )

    for provider in providers:
        try:
            secrets = _load_connector_secrets(tenant_id, provider)
            connector = get_connector(provider=provider, tenant_id=tenant_id, secrets=secrets)
            response = await connector.execute_action("lookup_indicator", {"indicator": indicator})
            score = float(response.get("reputation_score", 0.0))
            if score > best.reputation_score:
                best = ThreatIntelResult(
                    indicator=indicator,
                    is_malicious=bool(response.get("is_malicious", False)),
                    provider=provider,
                    reputation_score=score,
                    details=response.get("details", ""),
                )
        except Exception as exc:
            activity.logger.warning(
                "[%s] Threat-intel lookup failed for provider '%s': %s",
                tenant_id,
                provider,
                exc,
            )

    return best


@activity.defn
async def graph_enrich_alert(tenant_id: str, alert: DefenderDetectionFindingEvent) -> EnrichedAlert:
    action_result = await connector_execute_action(
        tenant_id,
        "microsoft_defender",
        "enrich_alert_context",
        {
            "alert_id": alert.alert_id,
            "severity": (alert.severity or "medium").lower(),
            "title": alert.title,
            "description": alert.description or "",
            "user_email": _vendor_value(alert, "user_email"),
            "device_id": _vendor_value(alert, "device_id"),
        },
    )
    payload = action_result.data.payload
    return EnrichedAlert(
        alert_id=str(payload.get("alert_id") or alert.alert_id),
        severity=str(payload.get("severity") or (alert.severity or "medium").lower()),
        title=str(payload.get("title") or alert.title),
        description=str(payload.get("description") or (alert.description or "")),
        user_display_name=payload.get("user_display_name"),
        user_department=payload.get("user_department"),
        device_display_name=payload.get("device_display_name"),
        device_os=payload.get("device_os"),
        device_compliance=payload.get("device_compliance"),
    )


@activity.defn
async def graph_get_alerts(tenant_id: str, user_email: str) -> list[dict]:
    action_result = await connector_execute_action(
        tenant_id,
        "microsoft_defender",
        "list_user_alerts",
        {"user_email": user_email},
    )
    return list(action_result.data.payload.get("alerts", []))[:10]


@activity.defn
async def graph_isolate_device(tenant_id: str, device_id: str) -> bool:
    action_result = await connector_execute_action(
        tenant_id,
        "microsoft_defender",
        "isolate_device",
        {"device_id": device_id, "comment": "Isolated by Secamo orchestrator"},
    )
    payload = action_result.data.payload
    if payload.get("found") is False:
        return False
    return bool(payload.get("submitted", True))


@activity.defn
async def graph_unisolate_device(tenant_id: str, device_id: str) -> bool:
    action_result = await connector_execute_action(
        tenant_id,
        "microsoft_defender",
        "unisolate_device",
        {"device_id": device_id, "comment": "Released from isolation by Secamo orchestrator"},
    )
    payload = action_result.data.payload
    if payload.get("found") is False:
        return False
    return bool(payload.get("submitted", True))


@activity.defn
async def device_get_context(tenant_id: str, device_id: str, provider: str = "microsoft_defender") -> DeviceContext | None:
    if provider.strip().lower() not in {"microsoft_defender", "defender", "microsoft_graph"}:
        return None
    action_result = await connector_execute_action(
        tenant_id,
        "microsoft_defender",
        "get_device_context",
        {"device_id": device_id},
    )
    payload = action_result.data.payload
    if payload.get("found") is False:
        return None
    return DeviceContext(
        provider="microsoft_defender",
        device_id=str(payload.get("device_id") or device_id),
        display_name=payload.get("display_name"),
        os_platform=payload.get("os_platform"),
        compliance_state=payload.get("compliance_state"),
        risk_score=payload.get("risk_score"),
    )


@activity.defn
async def graph_run_antivirus_scan(
    tenant_id: str,
    device_id: str,
    scan_type: str = "Quick",
) -> ConnectorActionResult:
    normalized_scan = "Full" if str(scan_type).lower() == "full" else "Quick"
    action_result = await connector_execute_action(
        tenant_id,
        "microsoft_defender",
        "run_antivirus_scan",
        {"device_id": device_id, "scan_type": normalized_scan},
    )
    payload = action_result.data.payload
    submitted = bool(payload.get("submitted", False))
    found = payload.get("found") is not False
    return ConnectorActionResult(
        provider="microsoft_defender",
        operation_type="action",
        success=submitted and found,
        details="scan action submitted" if submitted else "device not found",
        data=ConnectorActionData(action="run_antivirus_scan", payload=payload),
    )


@activity.defn
async def graph_list_noncompliant_devices(tenant_id: str) -> list[dict]:
    action_result = await connector_execute_action(
        tenant_id,
        "microsoft_defender",
        "list_noncompliant_devices",
        {},
    )
    return list(action_result.data.payload.get("devices", []))


@activity.defn
async def graph_confirm_user_compromised(tenant_id: str, user_id: str) -> bool:
    action_result = await connector_execute_action(
        tenant_id,
        "microsoft_defender",
        "confirm_user_compromised",
        {"user_id": user_id},
    )
    return bool(action_result.data.payload.get("confirmed", False))


@activity.defn
async def graph_dismiss_risky_user(tenant_id: str, user_id: str) -> bool:
    action_result = await connector_execute_action(
        tenant_id,
        "microsoft_defender",
        "dismiss_risky_user",
        {"user_id": user_id},
    )
    return bool(action_result.data.payload.get("dismissed", False))


@activity.defn
async def graph_get_signin_history(
    tenant_id: str,
    user_principal_name: str,
    top: int = 20,
) -> list[dict]:
    action_result = await connector_execute_action(
        tenant_id,
        "microsoft_defender",
        "get_signin_history",
        {"user_principal_name": user_principal_name, "top": top},
    )
    return list(action_result.data.payload.get("signins", []))


@activity.defn
async def graph_list_risky_users(
    tenant_id: str,
    min_risk_level: str,
) -> list[GraphRiskyUser]:
    action_result = await connector_execute_action(
        tenant_id,
        "microsoft_defender",
        "list_risky_users",
        {"min_risk_level": min_risk_level},
    )
    users = action_result.data.payload.get("users", [])
    return [_to_risky_user_result(item) for item in users]


@activity.defn
async def identity_get_risk_context(tenant_id: str, lookup_key: str, provider: str = "microsoft_graph") -> IdentityRiskContext | None:
    normalized = provider.strip().lower()
    if normalized not in {"microsoft_graph", "entra_id"}:
        return None
    action_result = await connector_execute_action(
        tenant_id,
        "microsoft_defender",
        "list_risky_users",
        {"lookup_key": lookup_key, "min_risk_level": "low"},
    )
    users = action_result.data.payload.get("users", [])
    if not users:
        return None
    risky_user = _to_risky_user_result(users[0])
    return IdentityRiskContext(
        provider=normalized,
        subject=risky_user.userPrincipalName or risky_user.userDisplayName or risky_user.id,
        risk_level=risky_user.riskLevel,
        risk_state=risky_user.riskState,
        risk_detail=risky_user.riskDetail,
    )


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
        notification_url=str(response_payload.get("notificationUrl") or (existing.notification_url if existing else "")),
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
