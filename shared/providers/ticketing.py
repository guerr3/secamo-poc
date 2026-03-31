from __future__ import annotations

from typing import Any

from connectors.base import BaseConnector
from shared.models import TicketData, TicketResult


class ConnectorTicketingProvider:
    """Ticketing provider backed by connector actions."""

    def __init__(
        self,
        *,
        ticketing_provider: str,
        connector: BaseConnector,
        ticket_base_url: str | None = None,
        default_project_key: str = "SOC",
    ) -> None:
        self._ticketing_provider = ticketing_provider
        self._connector = connector
        self._ticket_base_url = (ticket_base_url or "").rstrip("/")
        self._default_project_key = default_project_key

    def _to_ticket_result(self, payload: dict[str, Any], *, fallback_ticket_id: str = "", fallback_status: str = "open") -> TicketResult:
        ticket_id = str(payload.get("key") or payload.get("ticket_id") or payload.get("id") or fallback_ticket_id)
        status = str(payload.get("status") or fallback_status)
        url = f"{self._ticket_base_url}/browse/{ticket_id}" if self._ticket_base_url and ticket_id else ""
        return TicketResult(ticket_id=ticket_id, status=status, url=url)

    @staticmethod
    def _severity_to_priority(severity: str) -> str:
        mapping = {
            "critical": "Highest",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
        }
        return mapping.get((severity or "medium").lower(), "Medium")

    async def create_ticket(self, ticket_data: TicketData) -> TicketResult:
        payload = {
            "project_key": self._default_project_key,
            "title": ticket_data.title,
            "description": ticket_data.description,
            "issue_type": "Incident",
            "priority": self._severity_to_priority(ticket_data.severity),
            "labels": ["secamo", ticket_data.source_workflow, ticket_data.tenant_id],
        }
        result = await self._connector.execute_action("create_issue", payload)
        return self._to_ticket_result(result if isinstance(result, dict) else {})

    async def update_ticket(self, ticket_id: str, update_fields: dict[str, Any]) -> TicketResult:
        status_map = {
            "closed": "Done",
            "in_progress": "In Progress",
            "escalated": "Escalated",
        }
        next_status = update_fields.get("status")
        transition_name = status_map.get(str(next_status).lower()) if next_status else None

        fields = {
            **update_fields,
            **({"transition_name": transition_name} if transition_name else {}),
        }
        result = await self._connector.execute_action(
            "update_issue",
            {"ticket_id": ticket_id, "fields": fields},
        )
        response = result if isinstance(result, dict) else {}
        response.setdefault("ticket_id", ticket_id)
        response.setdefault("status", str(next_status or "updated"))
        return self._to_ticket_result(response, fallback_ticket_id=ticket_id, fallback_status=str(next_status or "updated"))

    async def close_ticket(self, ticket_id: str, resolution: str) -> TicketResult:
        await self._connector.execute_action(
            "close_issue",
            {
                "ticket_id": ticket_id,
                "transition_name": "Done",
                "resolution": resolution,
            },
        )
        return self._to_ticket_result(
            {"ticket_id": ticket_id, "status": "closed"},
            fallback_ticket_id=ticket_id,
            fallback_status="closed",
        )

    async def get_ticket_details(self, ticket_id: str) -> dict[str, Any]:
        details = await self._connector.execute_action("get_issue", {"ticket_id": ticket_id})
        payload = details if isinstance(details, dict) else {}
        fields = payload.get("fields", {}) if isinstance(payload.get("fields"), dict) else {}
        return {
            "ticket_id": payload.get("key") or ticket_id,
            "title": fields.get("summary", ""),
            "description": fields.get("description", ""),
            "severity": ((fields.get("priority") or {}).get("name") or "medium").lower(),
            "status": ((fields.get("status") or {}).get("name") or "open").lower(),
            "assignee": ((fields.get("assignee") or {}).get("emailAddress") or ""),
            "created": fields.get("created", ""),
            "provider": self._ticketing_provider,
        }
