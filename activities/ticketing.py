from __future__ import annotations

import asyncio

from temporalio import activity

from connectors.registry import get_connector
from shared.models import TenantSecrets, TicketData, TicketResult
from shared.ssm_client import get_secret_bundle


def _severity_to_priority(severity: str) -> str:
    mapping = {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }
    return mapping.get((severity or "medium").lower(), "Medium")


def _build_ticketing_secrets(tenant_id: str) -> TenantSecrets:
    raw = get_secret_bundle(tenant_id, "ticketing")
    return TenantSecrets(
        client_id="",
        client_secret="",
        tenant_azure_id="",
        jira_base_url=raw.get("jira_base_url") or raw.get("base_url"),
        jira_email=raw.get("jira_email"),
        jira_api_token=raw.get("jira_api_token") or raw.get("api_token"),
        project_key=raw.get("project_key"),
        project_type=(raw.get("project_type") or "standard").strip().lower(),
        jsm_service_desk_id=raw.get("jsm_service_desk_id"),
    )


async def _build_ticketing_secrets_async(tenant_id: str) -> TenantSecrets:
    return await asyncio.to_thread(_build_ticketing_secrets, tenant_id)


def _build_ticket_result(response: dict, secrets: TenantSecrets, fallback_id: str = "") -> TicketResult:
    ticket_id = response.get("key") or response.get("ticket_id") or fallback_id
    base = (secrets.jira_base_url or "").rstrip("/")
    url = f"{base}/browse/{ticket_id}" if base and ticket_id else ""
    status = response.get("status") or "open"
    return TicketResult(ticket_id=ticket_id, status=status, url=url)


@activity.defn
async def ticket_create(tenant_id: str, ticketing_provider: str, ticket_data: TicketData) -> TicketResult:
    activity.logger.info(f"[{tenant_id}] ticket_create: {ticket_data.title}")
    secrets = await _build_ticketing_secrets_async(tenant_id)
    connector = get_connector(provider=ticketing_provider, tenant_id=tenant_id, secrets=secrets)

    payload = {
        "project_key": secrets.project_key or "SOC",
        "title": ticket_data.title,
        "description": ticket_data.description,
        "issue_type": "Incident",
        "priority": _severity_to_priority(ticket_data.severity),
        "labels": ["secamo", ticket_data.source_workflow, tenant_id],
    }
    result = await connector.execute_action("create_issue", payload)
    return _build_ticket_result(result, secrets)


@activity.defn
async def ticket_update(tenant_id: str, ticketing_provider: str, ticket_id: str, update_fields: dict) -> TicketResult:
    activity.logger.info(f"[{tenant_id}] ticket_update: {ticket_id}")
    secrets = await _build_ticketing_secrets_async(tenant_id)
    connector = get_connector(provider=ticketing_provider, tenant_id=tenant_id, secrets=secrets)

    status_map = {
        "closed": "Done",
        "in_progress": "In Progress",
        "escalated": "Escalated",
    }
    next_status = update_fields.get("status")
    transition_name = status_map.get(str(next_status).lower()) if next_status else None

    jira_fields = {
        **update_fields,
        **({"transition_name": transition_name} if transition_name else {}),
    }
    result = await connector.execute_action(
        "update_issue",
        {"ticket_id": ticket_id, "fields": jira_fields},
    )
    return _build_ticket_result({**result, "status": next_status or "updated"}, secrets, fallback_id=ticket_id)


@activity.defn
async def ticket_close(tenant_id: str, ticketing_provider: str, ticket_id: str, resolution: str) -> TicketResult:
    activity.logger.info(f"[{tenant_id}] ticket_close: {ticket_id}")
    secrets = await _build_ticketing_secrets_async(tenant_id)
    connector = get_connector(provider=ticketing_provider, tenant_id=tenant_id, secrets=secrets)

    await connector.execute_action(
        "close_issue",
        {
            "ticket_id": ticket_id,
            "transition_name": "Done",
            "resolution": resolution,
        },
    )
    return _build_ticket_result({"ticket_id": ticket_id, "status": "closed"}, secrets, fallback_id=ticket_id)


@activity.defn
async def ticket_get_details(tenant_id: str, ticketing_provider: str, ticket_id: str) -> dict:
    activity.logger.info(f"[{tenant_id}] ticket_get_details: {ticket_id}")
    secrets = await _build_ticketing_secrets_async(tenant_id)
    connector = get_connector(provider=ticketing_provider, tenant_id=tenant_id, secrets=secrets)
    details = await connector.execute_action("get_issue", {"ticket_id": ticket_id})

    fields = details.get("fields", {})
    return {
        "ticket_id": details.get("key", ticket_id),
        "title": fields.get("summary", ""),
        "description": fields.get("description", ""),
        "severity": ((fields.get("priority") or {}).get("name") or "medium").lower(),
        "status": ((fields.get("status") or {}).get("name") or "open").lower(),
        "assignee": ((fields.get("assignee") or {}).get("emailAddress") or ""),
        "created": fields.get("created", ""),
    }
