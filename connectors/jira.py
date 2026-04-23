from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
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

    def _uses_jsm_project(self) -> bool:
        return (self.secrets.project_type or "standard").strip().lower() == "jsm"

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

            if response.status_code in (400, 401, 403, 404, 409, 422):
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

    async def _comment_marker_exists(self, issue_key: str, marker: str) -> bool:
        start_at = 0
        max_results = 50

        while True:
            response = await self._request_with_retry(
                "GET",
                f"{self._base_url()}/rest/api/3/issue/{issue_key}/comment",
                params={
                    "startAt": str(start_at),
                    "maxResults": str(max_results),
                },
            )
            body = response.json()
            comments = body.get("comments", [])
            for comment in comments:
                if marker in json.dumps(comment.get("body", ""), sort_keys=True):
                    return True

            total = int(body.get("total") or 0)
            start_at += len(comments)
            if not comments or start_at >= total:
                return False

    async def execute_action(self, action: str, payload: dict) -> dict:
        base_url = self._base_url()

        if action in ("create_ticket", "create_issue"):
            if self._uses_jsm_project():
                service_desk_id = str(payload.get("service_desk_id") or self.secrets.jsm_service_desk_id or "").strip()
                request_type_id = str(payload.get("request_type_id") or self.secrets.jsm_request_type_id or "").strip()
                if not service_desk_id:
                    raise ConnectorPermanentError(
                        "Missing jsm_service_desk_id for JSM customer request creation"
                    )
                if not request_type_id:
                    raise ConnectorPermanentError(
                        "Missing jsm_request_type_id for JSM customer request creation"
                    )

                request_field_values = payload.get("request_field_values")
                if not isinstance(request_field_values, dict):
                    request_field_values = {}
                request_field_values = {
                    **request_field_values,
                    "summary": request_field_values.get("summary") or payload["title"],
                    "description": request_field_values.get("description") or payload.get("description", ""),
                }

                request_payload: dict[str, Any] = {
                    "serviceDeskId": service_desk_id,
                    "requestTypeId": request_type_id,
                    "requestFieldValues": request_field_values,
                }
                raise_on_behalf_of = payload.get("raise_on_behalf_of")
                if isinstance(raise_on_behalf_of, str) and raise_on_behalf_of.strip():
                    request_payload["raiseOnBehalfOf"] = raise_on_behalf_of.strip()

                request_participants = payload.get("request_participants")
                if isinstance(request_participants, list) and request_participants:
                    request_payload["requestParticipants"] = [
                        str(item).strip() for item in request_participants if str(item).strip()
                    ]

                response = await self._request_with_retry(
                    "POST",
                    f"{base_url}/rest/servicedeskapi/request",
                    json=request_payload,
                )
                return response.json()

            project_key = str(payload.get("project_key") or self.secrets.project_key or "SOC").strip()
            if not project_key:
                raise ConnectorPermanentError("Missing Jira project key for ticket creation")

            fields: dict[str, Any] = {
                "project": {"key": project_key},
                "summary": payload["title"],
                "description": self._adf_text(payload.get("description", "")),
                "issuetype": {"name": payload.get("issue_type", "Task")},
            }
            priority = payload.get("priority")
            if isinstance(priority, str) and priority.strip():
                fields["priority"] = {"name": priority.strip()}
            labels = payload.get("labels")
            if isinstance(labels, list) and labels:
                fields["labels"] = [str(label) for label in labels if str(label).strip()]

            response = await self._request_with_retry(
                "POST",
                f"{base_url}/rest/api/3/issue",
                json={"fields": fields},
            )
            return response.json()

        if action in ("update_ticket", "update_issue"):
            issue_key = payload["ticket_id"]

            raw_fields = payload.get("fields") if isinstance(payload.get("fields"), dict) else {}
            issue_fields: dict[str, Any] = {}
            if "summary" in raw_fields:
                issue_fields["summary"] = raw_fields.get("summary")
            if "description" in raw_fields:
                description_value = raw_fields.get("description")
                issue_fields["description"] = (
                    self._adf_text(str(description_value)) if isinstance(description_value, str) else description_value
                )
            if "labels" in raw_fields:
                labels_value = raw_fields.get("labels")
                if isinstance(labels_value, list):
                    issue_fields["labels"] = [str(label) for label in labels_value if str(label).strip()]
            if "priority" in raw_fields:
                priority_value = raw_fields.get("priority")
                if isinstance(priority_value, str) and priority_value.strip():
                    issue_fields["priority"] = {"name": priority_value.strip()}
                elif isinstance(priority_value, dict):
                    issue_fields["priority"] = priority_value

            if issue_fields:
                await self._request_with_retry(
                    "PUT",
                    f"{base_url}/rest/api/3/issue/{issue_key}",
                    json={"fields": issue_fields},
                )

            comment = payload.get("comment")
            if isinstance(comment, str) and comment.strip():
                idempotency_key = str(payload.get("comment_idempotency_key") or "").strip()
                marker = f"[secamo-idempotency-key:{idempotency_key}]" if idempotency_key else ""

                should_post = True
                if marker:
                    should_post = not await self._comment_marker_exists(issue_key, marker)

                comment_text = comment.strip()
                if marker and marker not in comment_text:
                    comment_text = f"{comment_text}\n\n{marker}"

                if should_post:
                    await self._request_with_retry(
                        "POST",
                        f"{base_url}/rest/api/3/issue/{issue_key}/comment",
                        json={"body": self._adf_text(comment_text)},
                    )

            transition_id = payload.get("transition_id")
            transition_name = payload.get("transition_name")
            resolution = payload.get("resolution")
            if transition_id or transition_name or resolution:
                resolved_transition_id = str(transition_id).strip() if transition_id else ""
                if not resolved_transition_id:
                    resolved_transition_id = await self._resolve_transition_id(
                        issue_key,
                        transition_name=str(transition_name) if transition_name else None,
                    )

                transition_request: dict[str, Any] = {"transition": {"id": resolved_transition_id}}
                if resolution:
                    transition_request["fields"] = {"resolution": {"name": str(resolution)}}

                await self._request_with_retry(
                    "POST",
                    f"{base_url}/rest/api/3/issue/{issue_key}/transitions",
                    json=transition_request,
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
