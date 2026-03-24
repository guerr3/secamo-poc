from __future__ import annotations

import httpx
from temporalio import activity
from urllib.parse import quote

from activities._activity_errors import application_error_from_http_status
from shared.graph_client import get_graph_token
from shared.models import RiskyUserResult, TenantSecrets

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _escape_odata_literal(value: str) -> str:
    return value.replace("'", "''")


def _retry_after_seconds(response: httpx.Response) -> int | None:
    retry_after = response.headers.get("Retry-After")
    if not retry_after:
        return None
    try:
        return int(retry_after)
    except ValueError:
        return None


def _handle_http_error(tenant_id: str, provider: str, response: httpx.Response, action: str) -> None:
    if response.status_code >= 400:
        raise application_error_from_http_status(
            tenant_id,
            provider,
            action,
            response.status_code,
            retry_after_seconds=_retry_after_seconds(response),
        )


async def _paged_get(
    client: httpx.AsyncClient,
    url: str,
    headers: dict[str, str],
    *,
    params: dict[str, str] | None = None,
    max_pages: int = 10,
    limit: int | None = None,
) -> tuple[int, list[dict]]:
    items: list[dict] = []
    next_url: str | None = url
    next_params = params
    pages = 0
    final_status = 200

    while next_url and pages < max_pages:
        response = await client.get(next_url, headers=headers, params=next_params)
        final_status = response.status_code
        if response.status_code != 200:
            break
        body = response.json()
        page_items = body.get("value", [])
        if limit is not None and len(items) + len(page_items) > limit:
            page_items = page_items[: max(0, limit - len(items))]
        items.extend(page_items)
        if limit is not None and len(items) >= limit:
            break
        next_url = body.get("@odata.nextLink")
        next_params = None
        pages += 1

    return final_status, items


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
    _handle_http_error(tenant_id, "microsoft_graph", response, "graph_get_risky_user")
    if response.status_code != 200:
        raise application_error_from_http_status(
            tenant_id,
            "microsoft_graph",
            "graph_get_risky_user",
            response.status_code,
            retry_after_seconds=_retry_after_seconds(response),
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

    _handle_http_error(tenant_id, "microsoft_graph", response, "graph_confirm_user_compromised")
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

    _handle_http_error(tenant_id, "microsoft_graph", response, "graph_dismiss_risky_user")
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
    user_filter = f"userPrincipalName eq '{_escape_odata_literal(user_principal_name)}'"

    async with httpx.AsyncClient(timeout=30.0) as client:
        status, items = await _paged_get(
            client,
            f"{GRAPH_BASE}/auditLogs/signIns",
            _auth_headers(token),
            params={"$filter": user_filter, "$top": str(min(capped_top, 100))},
            limit=capped_top,
        )

    if status != 200:
        raise application_error_from_http_status(
            tenant_id,
            "microsoft_graph",
            "graph_get_signin_history",
            status,
        )
    return items


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
        status, items = await _paged_get(
            client,
            f"{GRAPH_BASE}/identityProtection/riskyUsers",
            _auth_headers(token),
            params={"$filter": filter_q, "$top": "500"},
            limit=500,
        )

    if status != 200:
        raise application_error_from_http_status(
            tenant_id,
            "microsoft_graph",
            "graph_list_risky_users",
            status,
        )

    return [_to_risky_user_result(item) for item in items]
