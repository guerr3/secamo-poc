from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from connectors.base import BaseConnector
from shared.models import CanonicalEvent


class JiraConnector(BaseConnector):
    """Jira Cloud connector for ticketing operations."""

    @property
    def provider(self) -> str:
        return "jira"

    def _auth(self) -> tuple[str, str]:
        if not self.secrets.jira_email or not self.secrets.jira_api_token:
            raise ValueError("Missing jira_email or jira_api_token in tenant secrets")
        return self.secrets.jira_email, self.secrets.jira_api_token

    def _base_url(self) -> str:
        if not self.secrets.jira_base_url:
            raise ValueError("Missing jira_base_url in tenant secrets")
        return self.secrets.jira_base_url.rstrip("/")

    @staticmethod
    def _adf_text(text: str) -> dict:
        return {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": text or ""}],
                }
            ],
        }

    async def fetch_events(self, query: dict) -> list[CanonicalEvent]:
        jql = query.get("jql", "ORDER BY created DESC")
        url = f"{self._base_url()}/rest/api/3/search"
        async with httpx.AsyncClient(timeout=20.0, auth=self._auth()) as client:
            response = await client.post(url, json={"jql": jql, "maxResults": int(query.get("max_results", 20))})
            response.raise_for_status()
            body = response.json()

        events: list[CanonicalEvent] = []
        for issue in body.get("issues", []):
            fields = issue.get("fields", {})
            events.append(
                CanonicalEvent(
                    event_type="jira.issue",
                    tenant_id=self.tenant_id,
                    provider=self.provider,
                    external_event_id=issue.get("id"),
                    subject=issue.get("key"),
                    severity=(fields.get("priority") or {}).get("name"),
                    occurred_at=datetime.now(timezone.utc),
                    payload={
                        "issue_id": issue.get("id"),
                        "issue_key": issue.get("key"),
                        "summary": fields.get("summary"),
                        "status": (fields.get("status") or {}).get("name"),
                    },
                )
            )
        return events

    async def execute_action(self, action: str, payload: dict) -> dict:
        base_url = self._base_url()
        auth = self._auth()

        async with httpx.AsyncClient(timeout=20.0, auth=auth) as client:
            if action in ("create_ticket", "create_issue"):
                response = await client.post(
                    f"{base_url}/rest/api/3/issue",
                    json={
                        "fields": {
                            "project": {"key": payload["project_key"]},
                            "summary": payload["title"],
                            "description": self._adf_text(payload.get("description", "")),
                            "issuetype": {"name": payload.get("issue_type", "Task")},
                        }
                    },
                )
                response.raise_for_status()
                return response.json()

            if action in ("update_ticket", "update_issue"):
                issue_key = payload["ticket_id"]
                response = await client.put(
                    f"{base_url}/rest/api/3/issue/{issue_key}",
                    json={
                        "fields": {
                            **payload.get("fields", {}),
                            **(
                                {"description": self._adf_text(str(payload["fields"]["description"]))}
                                if isinstance(payload.get("fields", {}).get("description"), str)
                                else {}
                            ),
                        }
                    },
                )
                response.raise_for_status()
                return {"ticket_id": issue_key, "updated": True}

            if action in ("close_ticket", "close_issue"):
                issue_key = payload["ticket_id"]
                transition_id = payload["transition_id"]
                response = await client.post(
                    f"{base_url}/rest/api/3/issue/{issue_key}/transitions",
                    json={"transition": {"id": str(transition_id)}},
                )
                response.raise_for_status()
                return {"ticket_id": issue_key, "closed": True}

            if action in ("get_ticket", "get_issue"):
                issue_key = payload["ticket_id"]
                response = await client.get(f"{base_url}/rest/api/3/issue/{issue_key}")
                response.raise_for_status()
                return response.json()

        raise ValueError(f"Unsupported action '{action}' for provider '{self.provider}'")

    async def health_check(self) -> dict:
        url = f"{self._base_url()}/rest/api/3/myself"
        async with httpx.AsyncClient(timeout=15.0, auth=self._auth()) as client:
            response = await client.get(url)
            return {
                "healthy": response.status_code == 200,
                "status_code": response.status_code,
                "provider": self.provider,
            }
