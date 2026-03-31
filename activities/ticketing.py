from __future__ import annotations

import asyncio

from temporalio import activity

from activities.tenant import get_tenant_config
from shared.models import TicketData, TicketResult
from shared.providers.factory import get_ticketing_provider
from shared.ssm_client import get_secret_bundle


async def _load_secret_bundle_async(tenant_id: str) -> dict[str, str]:
    return await asyncio.to_thread(get_secret_bundle, tenant_id, "ticketing")


async def _get_ticketing_provider(tenant_id: str, ticketing_provider: str):
    config = await get_tenant_config(tenant_id)
    if config.ticketing_provider != ticketing_provider:
        config = config.model_copy(update={"ticketing_provider": ticketing_provider})
    secrets = await _load_secret_bundle_async(tenant_id)
    return await get_ticketing_provider(tenant_id, secrets, config)


@activity.defn
async def ticket_create(tenant_id: str, ticketing_provider: str, ticket_data: TicketData) -> TicketResult:
    activity.logger.info(f"[{tenant_id}] ticket_create: {ticket_data.title}")
    provider = await _get_ticketing_provider(tenant_id, ticketing_provider)
    return await provider.create_ticket(ticket_data)


@activity.defn
async def ticket_update(tenant_id: str, ticketing_provider: str, ticket_id: str, update_fields: dict) -> TicketResult:
    activity.logger.info(f"[{tenant_id}] ticket_update: {ticket_id}")
    provider = await _get_ticketing_provider(tenant_id, ticketing_provider)
    return await provider.update_ticket(ticket_id, update_fields)


@activity.defn
async def ticket_close(tenant_id: str, ticketing_provider: str, ticket_id: str, resolution: str) -> TicketResult:
    activity.logger.info(f"[{tenant_id}] ticket_close: {ticket_id}")
    provider = await _get_ticketing_provider(tenant_id, ticketing_provider)
    return await provider.close_ticket(ticket_id, resolution)


@activity.defn
async def ticket_get_details(tenant_id: str, ticketing_provider: str, ticket_id: str) -> dict:
    activity.logger.info(f"[{tenant_id}] ticket_get_details: {ticket_id}")
    provider = await _get_ticketing_provider(tenant_id, ticketing_provider)
    return await provider.get_ticket_details(ticket_id)
