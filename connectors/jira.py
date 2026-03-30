from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import httpx

from connectors.base import BaseConnector
from connectors.errors import (
    ConnectorConfigurationError,
    ConnectorPermanentError,
    ConnectorTransientError,
    ConnectorUnsupportedActionError,
)
from shared.models import Envelope, IamOnboardingEvent, LifecycleAction, VendorExtension
from shared.models.mappers import build_connector_correlation, build_envelope


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

    async def fetch_events(self, query: dict) -> list[Envelope]:
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

        events: list[Envelope] = []
        for issue in body.get("issues", []):
            fields = issue.get("fields", {})
            occurred_at = self._parse_iso_datetime(fields.get("updated") or fields.get("created"))
            if occurred_at is None:
                occurred_at = datetime.now(timezone.utc)
            issue_id = str(issue.get("id") or "")
            issue_key = str(issue.get("key") or issue_id)
            user_email = str(((fields.get("reporter") or {}).get("emailAddress") or "unknown@example.com"))
            payload = IamOnboardingEvent(
                event_type="iam.onboarding",
                activity_id=3001,
                activity_name="jira.issue",
                user_email=user_email,
                action=LifecycleAction.UPDATE,
                user_data={"email": user_email, "display_name": str((fields.get("reporter") or {}).get("displayName") or "")},
                vendor_extensions={
                    "issue_key": VendorExtension(source="jira", value=issue_key),
                    "status": VendorExtension(source="jira", value=(fields.get("status") or {}).get("name")),
                },
            )
            correlation_id = issue_id or issue_key
            events.append(
                build_envelope(
                    tenant_id=self.tenant_id,
                    source_provider=self.provider,
                    occurred_at=occurred_at,
                    correlation=build_connector_correlation(
                        tenant_id=self.tenant_id,
                        event_name=payload.event_type,
                        correlation_id=correlation_id,
                        provider_event_id=issue_key,
                    ),
                    payload=payload,
                    provider_event_id=issue_id or None,
                    metadata={"provider_event_type": "jira:issue_updated", "summary": fields.get("summary") or ""},
                )
            )
        return events

    async def _resolve_transition_id(self, issue_key: str, transition_name: str | None = None) -> str:
        response = await self._request_with_retry(
            "GET",
            f"{self._base_url()}/rest/api/3/issue/{issue_key}/transitions",
        )
        transitions = response.json().get("transitions", [])
        if not transitions:
            raise ConnectorPermanentError(f"No available transitions for issue '{issue_key}'")

        if transition_name:
            desired = transition_name.strip().lower()
            for transition in transitions:
                name = str(transition.get("name") or "").strip().lower()
                if name == desired:
                    transition_id = str(transition.get("id") or "").strip()
                    if transition_id:
                        return transition_id

        preferred_names = {"done", "closed", "close", "resolve", "resolved"}
        for transition in transitions:
            name = str(transition.get("name") or "").strip().lower()
            transition_id = str(transition.get("id") or "").strip()
            if transition_id and name in preferred_names:
                return transition_id

        fallback_id = str(transitions[0].get("id") or "").strip()
        if fallback_id:
            return fallback_id
        raise ConnectorPermanentError(f"Unable to resolve transition for issue '{issue_key}'")

    async def execute_action(self, action: str, payload: dict) -> dict:
        base_url = self._base_url()

        if action in ("create_ticket", "create_issue"):
            project_key = str(payload.get("project_key") or self.secrets.project_key or "SOC").strip()
            if not project_key:
                raise ConnectorPermanentError("Missing Jira project key for ticket creation")
            response = await self._request_with_retry(
                "POST",
                f"{base_url}/rest/api/3/issue",
                json={
                    "fields": {
                        "project": {"key": project_key},
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
            transition_id = payload.get("transition_id")
            if not transition_id:
                transition_id = await self._resolve_transition_id(
                    issue_key,
                    transition_name=payload.get("transition_name"),
                )

            transition_request: dict[str, Any] = {"transition": {"id": str(transition_id)}}
            resolution = payload.get("resolution")
            if resolution:
                transition_request["fields"] = {"resolution": {"name": str(resolution)}}

            await self._request_with_retry(
                "POST",
                f"{base_url}/rest/api/3/issue/{issue_key}/transitions",
                json=transition_request,
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
