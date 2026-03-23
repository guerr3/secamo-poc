from __future__ import annotations

from urllib.parse import quote

import httpx
from temporalio import activity

from activities._activity_errors import application_error_from_http_status
from shared.graph_client import get_graph_token
from shared.models import RiskyUserResult, TenantSecrets

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _handle_http_error(tenant_id: str, provider: str, status: int, action: str) -> None:
    if status >= 400:
        raise application_error_from_http_status(tenant_id, provider, action, status)


def _to_risky_user_result(payload: dict) -> RiskyUserResult:
    return RiskyUserResult(
        id=payload.get("id", ""),
        isDeleted=payload.get("isDeleted"),
        isProcessing=payload.get("isProcessing"),
        riskLastUpdatedDateTime=payload.get("riskLastUpdatedDateTime"),
        riskLevel=payload.get("riskLevel"),
        riskState=payload.get("riskState"),
        riskDetail=payload.get("riskDetail"),
        userDisplayName=payload.get("userDisplayName"),
        userPrincipalName=payload.get("userPrincipalName"),
    )


@activity.defn
async def graph_get_risky_user(tenant_id: str, risky_user_id: str, secrets: TenantSecrets) -> RiskyUserResult | None:
    activity.logger.info(f"[{tenant_id}] graph_get_risky_user: {risky_user_id}")
    token = await get_graph_token(secrets)

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            f"{GRAPH_BASE}/identityProtection/riskyUsers/{quote(risky_user_id)}",
            headers=_auth_headers(token),
        )

    if response.status_code == 404:
        return None
    _handle_http_error(tenant_id, "microsoft_graph", response.status_code, "graph_get_risky_user")
    if response.status_code != 200:
        raise application_error_from_http_status(
            tenant_id,
            "microsoft_graph",
            "graph_get_risky_user",
            response.status_code,
        )

    return _to_risky_user_result(response.json())


@activity.defn
async def graph_confirm_user_compromised(tenant_id: str, user_id: str, secrets: TenantSecrets) -> bool:
    activity.logger.info(f"[{tenant_id}] graph_confirm_user_compromised: {user_id}")
    token = await get_graph_token(secrets)
    payload = {"userIds": [user_id]}

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{GRAPH_BASE}/identityProtection/riskyUsers/confirmCompromised",
            headers=_auth_headers(token),
            json=payload,
        )

    _handle_http_error(tenant_id, "microsoft_graph", response.status_code, "graph_confirm_user_compromised")
    return response.status_code == 204


@activity.defn
async def graph_dismiss_risky_user(tenant_id: str, user_id: str, secrets: TenantSecrets) -> bool:
    activity.logger.info(f"[{tenant_id}] graph_dismiss_risky_user: {user_id}")
    token = await get_graph_token(secrets)
    payload = {"userIds": [user_id]}

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{GRAPH_BASE}/identityProtection/riskyUsers/dismiss",
            headers=_auth_headers(token),
            json=payload,
        )

    _handle_http_error(tenant_id, "microsoft_graph", response.status_code, "graph_dismiss_risky_user")
    return response.status_code == 204


@activity.defn
async def graph_get_signin_history(
    tenant_id: str,
    user_principal_name: str,
    secrets: TenantSecrets,
    top: int = 20,
) -> list[dict]:
    activity.logger.info(f"[{tenant_id}] graph_get_signin_history: {user_principal_name}")
    token = await get_graph_token(secrets)
    capped_top = min(max(int(top), 1), 1000)
    user_filter = quote(f"userPrincipalName eq '{user_principal_name}'")

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            f"{GRAPH_BASE}/auditLogs/signIns?$filter={user_filter}&$top={capped_top}",
            headers=_auth_headers(token),
        )

    _handle_http_error(tenant_id, "microsoft_graph", response.status_code, "graph_get_signin_history")
    if response.status_code != 200:
        raise application_error_from_http_status(
            tenant_id,
            "microsoft_graph",
            "graph_get_signin_history",
            response.status_code,
        )
    return response.json().get("value", [])


@activity.defn
async def graph_list_risky_users(
    tenant_id: str,
    min_risk_level: str,
    secrets: TenantSecrets,
) -> list[RiskyUserResult]:
    activity.logger.info(f"[{tenant_id}] graph_list_risky_users min={min_risk_level}")
    token = await get_graph_token(secrets)

    risk_levels = ["low", "medium", "high"]
    normalized = str(min_risk_level or "low").lower()
    if normalized not in risk_levels:
        normalized = "low"

    allowed = risk_levels[risk_levels.index(normalized):]
    filter_q = " or ".join(f"riskLevel eq '{lvl}'" for lvl in allowed)

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            f"{GRAPH_BASE}/identityProtection/riskyUsers?$filter={quote(filter_q)}&$top=500",
            headers=_auth_headers(token),
        )

    _handle_http_error(tenant_id, "microsoft_graph", response.status_code, "graph_list_risky_users")
    if response.status_code != 200:
        raise application_error_from_http_status(
            tenant_id,
            "microsoft_graph",
            "graph_list_risky_users",
            response.status_code,
        )

    return [_to_risky_user_result(item) for item in response.json().get("value", [])]
