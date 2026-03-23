from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

import httpx

from connectors.base import BaseConnector
from connectors.errors import (
    ConnectorConfigurationError,
    ConnectorPermanentError,
    ConnectorTransientError,
    ConnectorUnsupportedActionError,
)
from shared.models import CanonicalEvent


class JiraConnector(BaseConnector):
    """Jira Cloud connector for ticketing operations."""

    _MAX_ATTEMPTS = 3

    @property
    def provider(self) -> str:
        return "jira"

    def _auth(self) -> tuple[str, str]:
        if not self.secrets.jira_email or not self.secrets.jira_api_token:
            raise ConnectorConfigurationError("Missing jira_email or jira_api_token in tenant secrets")
        return self.secrets.jira_email, self.secrets.jira_api_token

    def _base_url(self) -> str:
        if not self.secrets.jira_base_url:
            raise ConnectorConfigurationError("Missing jira_base_url in tenant secrets")
        return self.secrets.jira_base_url.rstrip("/")

    @staticmethod
    def _retry_delay_seconds(retry_after_header: str | None, attempt: int) -> float:
        if retry_after_header:
            try:
                return max(0.0, float(retry_after_header))
            except ValueError:
                pass
        return float(min(2 ** (attempt - 1), 30))

    async def _request_with_retry(
        self,
        method: str,
        url: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
        timeout: float = 20.0,
    ) -> httpx.Response:
        auth = self._auth()
        last_error: Exception | None = None

        for attempt in range(1, self._MAX_ATTEMPTS + 1):
            try:
                # Open a new connection on each attempt to avoid sticky failures.
                async with httpx.AsyncClient(timeout=timeout, auth=auth) as client:
                    response = await client.request(method=method, url=url, json=json, params=params)
            except httpx.RequestError as exc:
                last_error = exc
                if attempt == self._MAX_ATTEMPTS:
                    break
                await asyncio.sleep(self._retry_delay_seconds(None, attempt))
                continue

            if response.status_code in (429, 503):
                if attempt == self._MAX_ATTEMPTS:
                    raise ConnectorTransientError(
                        f"Jira request throttled/unavailable after retries: status={response.status_code} url={url}"
                    )
                await asyncio.sleep(self._retry_delay_seconds(response.headers.get("Retry-After"), attempt))
                continue

            if response.status_code in (400, 401, 403, 404):
                raise ConnectorPermanentError(
                    f"Jira request rejected: status={response.status_code} url={url}"
                )

            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                if 500 <= response.status_code < 600:
                    last_error = exc
                    if attempt == self._MAX_ATTEMPTS:
                        break
                    await asyncio.sleep(self._retry_delay_seconds(response.headers.get("Retry-After"), attempt))
                    continue
                raise ConnectorPermanentError(
                    f"Jira request failed: status={response.status_code} url={url}"
                ) from exc

            return response

        raise ConnectorTransientError(f"Jira request failed after retries: {url}") from last_error

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

    @staticmethod
    def _parse_iso_datetime(value: str | None) -> datetime | None:
        if not value:
            return None
        parsed = value
        if parsed.endswith("Z"):
            parsed = parsed[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(parsed)
        except ValueError:
            return None

    async def fetch_events(self, query: dict) -> list[CanonicalEvent]:
        since = query.get("since")
        if since:
            jql = f'updated > "{since}" ORDER BY updated ASC'
        else:
            jql = query.get("jql", "ORDER BY created DESC")

        max_results = int(query.get("max_results", query.get("top", 20)))
        url = f"{self._base_url()}/rest/api/3/search"
        response = await self._request_with_retry(
            "POST",
            url,
            json={"jql": jql, "maxResults": max_results},
        )
        body = response.json()

        events: list[CanonicalEvent] = []
        for issue in body.get("issues", []):
            fields = issue.get("fields", {})
            occurred_at = self._parse_iso_datetime(fields.get("updated") or fields.get("created"))
            events.append(
                CanonicalEvent(
                    event_type="jira.issue",
                    tenant_id=self.tenant_id,
                    provider=self.provider,
                    external_event_id=issue.get("id"),
                    subject=issue.get("key"),
                    severity=(fields.get("priority") or {}).get("name"),
                    occurred_at=occurred_at,
                    payload={
                        "issue_id": issue.get("id"),
                        "issue_key": issue.get("key"),
                        "summary": fields.get("summary"),
                        "status": (fields.get("status") or {}).get("name"),
                        "provider_event_type": "jira:issue_updated",
                    },
                )
            )
        return events

    async def execute_action(self, action: str, payload: dict) -> dict:
        base_url = self._base_url()

        if action in ("create_ticket", "create_issue"):
            response = await self._request_with_retry(
                "POST",
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
            return response.json()

        if action in ("update_ticket", "update_issue"):
            issue_key = payload["ticket_id"]
            await self._request_with_retry(
                "PUT",
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
            return {"ticket_id": issue_key, "updated": True}

        if action in ("close_ticket", "close_issue"):
            issue_key = payload["ticket_id"]
            transition_id = payload["transition_id"]
            await self._request_with_retry(
                "POST",
                f"{base_url}/rest/api/3/issue/{issue_key}/transitions",
                json={"transition": {"id": str(transition_id)}},
            )
            return {"ticket_id": issue_key, "closed": True}

        if action in ("get_ticket", "get_issue"):
            issue_key = payload["ticket_id"]
            response = await self._request_with_retry(
                "GET",
                f"{base_url}/rest/api/3/issue/{issue_key}",
            )
            return response.json()

        raise ConnectorUnsupportedActionError(
            f"Unsupported action '{action}' for provider '{self.provider}'"
        )

    async def health_check(self) -> dict:
        url = f"{self._base_url()}/rest/api/3/myself"
        response = await self._request_with_retry("GET", url, timeout=15.0)
        return {
            "healthy": response.status_code == 200,
            "status_code": response.status_code,
            "provider": self.provider,
        }
