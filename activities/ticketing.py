from temporalio import activity
from shared.models import TicketData, TicketResult


@activity.defn
async def ticket_create(
    tenant_id: str,
    ticket_data: TicketData,
) -> TicketResult:
    """
    Maakt een nieuw ticket aan in het ticketing-systeem.
    Later: integratie met Jira Service Management, ServiceNow of Halo ITSM.
    """
    activity.logger.info(
        f"[{tenant_id}] Ticket aanmaken: '{ticket_data.title}' "
        f"(severity: {ticket_data.severity})"
    )

    # TODO: replace with real ticketing API call
    return TicketResult(
        ticket_id="TKT-2025-00042",
        status="open",
        url="https://ticketing.secamo.be/tickets/TKT-2025-00042",
    )


@activity.defn
async def ticket_update(
    tenant_id: str,
    ticket_id: str,
    update_fields: dict,
) -> TicketResult:
    """
    Update een bestaand ticket (status, beschrijving, assignee, etc.).
    Later: PUT/PATCH naar ticketing API.
    """
    activity.logger.info(
        f"[{tenant_id}] Ticket '{ticket_id}' updaten met {list(update_fields.keys())}"
    )

    # TODO: replace with real ticketing API call
    return TicketResult(
        ticket_id=ticket_id,
        status=update_fields.get("status", "updated"),
        url=f"https://ticketing.secamo.be/tickets/{ticket_id}",
    )


@activity.defn
async def ticket_close(
    tenant_id: str,
    ticket_id: str,
    resolution: str,
) -> TicketResult:
    """
    Sluit een ticket met een opgegeven resolutie.
    Later: PUT naar ticketing API met status=closed.
    """
    activity.logger.info(
        f"[{tenant_id}] Ticket '{ticket_id}' sluiten — resolutie: {resolution}"
    )

    # TODO: replace with real ticketing API call
    return TicketResult(
        ticket_id=ticket_id,
        status="closed",
        url=f"https://ticketing.secamo.be/tickets/{ticket_id}",
    )


@activity.defn
async def ticket_get_details(
    tenant_id: str,
    ticket_id: str,
) -> dict:
    """
    Haalt de details van een ticket op.
    Later: GET van ticketing API.
    """
    activity.logger.info(
        f"[{tenant_id}] Ticket details ophalen voor '{ticket_id}'"
    )

    # TODO: replace with real ticketing API call
    return {
        "ticket_id": ticket_id,
        "title": "Stub ticket title",
        "description": "Stub ticket description",
        "severity": "high",
        "status": "open",
        "assignee": "analyst@secamo.be",
        "created": "2025-01-15T10:30:00Z",
    }
