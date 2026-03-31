from __future__ import annotations

import os
import secrets as secret_tokens
from urllib.parse import urlparse

import boto3
import httpx

from connectors.errors import ConnectorConfigurationError, ConnectorPermanentError, ConnectorTransientError
from shared.providers.contracts import TenantSecrets
from shared.ssm_client import get_secret, put_secret


class JiraProvisioner:
    """Provision Jira Service Management onboarding assets for a tenant."""

    _MAX_ATTEMPTS = 3

    def _auth(self, tenant_secrets: TenantSecrets) -> tuple[str, str]:
        if not tenant_secrets.jira_email or not tenant_secrets.jira_api_token:
            raise ConnectorConfigurationError("Missing jira_email or jira_api_token in tenant secrets")
        return tenant_secrets.jira_email, tenant_secrets.jira_api_token

    def _base_url(self, tenant_secrets: TenantSecrets) -> str:
        if not tenant_secrets.jira_base_url:
            raise ConnectorConfigurationError("Missing jira_base_url in tenant secrets")
        return tenant_secrets.jira_base_url.rstrip("/")

    async def _request_with_retry(
        self,
        method: str,
        url: str,
        auth: tuple[str, str],
        *,
        json: dict | None = None,
        params: dict | None = None,
        timeout: float = 20.0,
    ) -> httpx.Response:
        last_error: Exception | None = None

        for attempt in range(1, self._MAX_ATTEMPTS + 1):
            try:
                async with httpx.AsyncClient(timeout=timeout, auth=auth) as client:
                    response = await client.request(method=method, url=url, json=json, params=params)
            except httpx.RequestError as exc:
                last_error = exc
                if attempt == self._MAX_ATTEMPTS:
                    break
                continue

            if response.status_code in (429, 503):
                if attempt == self._MAX_ATTEMPTS:
                    raise ConnectorTransientError(
                        f"Jira provisioning throttled/unavailable after retries: status={response.status_code} url={url}"
                    )
                continue

            if response.status_code in (400, 401, 403, 404):
                raise ConnectorPermanentError(
                    f"Jira provisioning request rejected: status={response.status_code} url={url}"
                )

            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                if 500 <= response.status_code < 600:
                    last_error = exc
                    if attempt == self._MAX_ATTEMPTS:
                        break
                    continue
                raise ConnectorPermanentError(
                    f"Jira provisioning request failed: status={response.status_code} url={url}"
                ) from exc

            return response

        raise ConnectorTransientError(f"Jira provisioning request failed after retries: {url}") from last_error

    @staticmethod
    def _normalize_base_url(value: str) -> str:
        parsed = urlparse(value)
        if not parsed.scheme or not parsed.netloc:
            raise ConnectorConfigurationError("Invalid public callback URL for Jira provisioning")
        return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")

    @staticmethod
    def _resolve_callback_base_url() -> str:
        env_base = (os.environ.get("SECAMO_PUBLIC_BASE_URL") or "").strip()
        if env_base:
            return JiraProvisioner._normalize_base_url(env_base)

        hitl_endpoint = (os.environ.get("HITL_ENDPOINT_BASE_URL") or "").strip()
        if hitl_endpoint:
            return JiraProvisioner._normalize_base_url(hitl_endpoint)

        name_prefix = os.environ.get("HITL_NAME_PREFIX", "secamo-temporal-test").strip() or "secamo-temporal-test"
        parameter_name = f"/{name_prefix}/hitl/endpoint_base_url"

        ssm = boto3.client("ssm", region_name="eu-west-1")
        response = ssm.get_parameter(Name=parameter_name, WithDecryption=False)
        endpoint_value = (response.get("Parameter", {}).get("Value") or "").strip()
        if not endpoint_value:
            raise ConnectorConfigurationError(
                f"Missing callback base URL configuration. Set SECAMO_PUBLIC_BASE_URL or SSM parameter {parameter_name}"
            )
        return JiraProvisioner._normalize_base_url(endpoint_value)

    @staticmethod
    def _ensure_secret_value(tenant_id: str, path: str) -> str:
        existing = (get_secret(tenant_id, path) or "").strip()
        if existing:
            return existing

        generated = secret_tokens.token_urlsafe(32)
        put_secret(
            tenant_id=tenant_id,
            path=path,
            value=generated,
            parameter_type="SecureString",
            overwrite=True,
        )
        return generated

    async def _list_webhooks(self, *, base_url: str, auth: tuple[str, str]) -> list[dict]:
        response = await self._request_with_retry("GET", f"{base_url}/rest/webhooks/1.0/webhook", auth)
        payload = response.json()
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict):
            values = payload.get("values")
            if isinstance(values, list):
                return [item for item in values if isinstance(item, dict)]
        return []

    async def _register_webhook(
        self,
        *,
        base_url: str,
        auth: tuple[str, str],
        webhook_name: str,
        webhook_description: str,
        callback_url: str,
        project_key: str,
        shared_secret: str,
    ) -> None:
        payload = {
            "name": webhook_name,
            "description": webhook_description,
            "url": callback_url,
            "events": ["jira:issue_created", "jira:issue_updated"],
            "filters": {
                "issue-related-events-section": f"project = {project_key}",
            },
            "excludeBody": False,
            "secret": shared_secret,
        }
        await self._request_with_retry(
            "POST",
            f"{base_url}/rest/webhooks/1.0/webhook",
            auth,
            json=payload,
        )

    async def _ensure_webhook(
        self,
        *,
        base_url: str,
        auth: tuple[str, str],
        project_key: str,
        callback_url: str,
        webhook_name: str,
        webhook_description: str,
        shared_secret: str,
    ) -> None:
        webhooks = await self._list_webhooks(base_url=base_url, auth=auth)
        callback_lower = callback_url.lower()
        for webhook in webhooks:
            url = str(webhook.get("url") or "").strip().lower()
            if url == callback_lower:
                return

        await self._register_webhook(
            base_url=base_url,
            auth=auth,
            webhook_name=webhook_name,
            webhook_description=webhook_description,
            callback_url=callback_url,
            project_key=project_key,
            shared_secret=shared_secret,
        )

    async def _discover_service_desk_id(
        self,
        *,
        base_url: str,
        auth: tuple[str, str],
        project_key: str,
    ) -> str:
        response = await self._request_with_retry(
            "GET",
            f"{base_url}/rest/servicedeskapi/servicedesk",
            auth,
            params={"projectKey": project_key},
        )
        payload = response.json()
        values = payload.get("values") if isinstance(payload, dict) else None
        candidates = values if isinstance(values, list) else []

        if not candidates:
            fallback_response = await self._request_with_retry(
                "GET",
                f"{base_url}/rest/servicedeskapi/servicedesk",
                auth,
            )
            fallback_payload = fallback_response.json()
            values = fallback_payload.get("values") if isinstance(fallback_payload, dict) else None
            candidates = values if isinstance(values, list) else []

        project_key_lower = project_key.strip().lower()
        for item in candidates:
            if not isinstance(item, dict):
                continue
            candidate_project_key = str(item.get("projectKey") or "").strip().lower()
            if candidate_project_key == project_key_lower:
                service_desk_id = str(item.get("id") or "").strip()
                if service_desk_id:
                    return service_desk_id

        raise ConnectorPermanentError(f"Unable to find JSM service desk for project_key='{project_key}'")

    @staticmethod
    def _persist_ticketing_fields(tenant_id: str, values: dict[str, str]) -> None:
        for key, value in values.items():
            put_secret(
                tenant_id=tenant_id,
                path=f"ticketing/{key}",
                value=value,
                parameter_type="String",
                overwrite=True,
            )

    async def provision_jsm_tenant(self, tenant_id: str, tenant_secrets: TenantSecrets) -> TenantSecrets:
        """Ensure JSM onboarding prerequisites exist and persist discovered tenant fields."""
        project_type = (tenant_secrets.project_type or "standard").strip().lower()
        if project_type != "jsm":
            return tenant_secrets

        if not tenant_secrets.project_key:
            raise ConnectorConfigurationError("Missing project_key in tenant ticketing secrets")

        auth = self._auth(tenant_secrets)
        base_url = self._base_url(tenant_secrets)
        callback_base = self._resolve_callback_base_url()

        ingress_secret = self._ensure_secret_value(tenant_id, "webhooks/jira_secret")
        hitl_secret = self._ensure_secret_value(tenant_id, "hitl/jira_webhook_secret")

        await self._ensure_webhook(
            base_url=base_url,
            auth=auth,
            project_key=tenant_secrets.project_key,
            callback_url=f"{callback_base}/api/v1/ingress/event/{tenant_id}",
            webhook_name=f"secamo-{tenant_id}-ingress",
            webhook_description="Secamo generic Jira ingress webhook",
            shared_secret=ingress_secret,
        )

        await self._ensure_webhook(
            base_url=base_url,
            auth=auth,
            project_key=tenant_secrets.project_key,
            callback_url=f"{callback_base}/api/v1/hitl/jira?tenant_id={tenant_id}",
            webhook_name=f"secamo-{tenant_id}-hitl",
            webhook_description="Secamo Jira HiTL approval webhook",
            shared_secret=hitl_secret,
        )

        service_desk_id = (tenant_secrets.jsm_service_desk_id or "").strip()
        if not service_desk_id:
            service_desk_id = await self._discover_service_desk_id(
                base_url=base_url,
                auth=auth,
                project_key=tenant_secrets.project_key,
            )

        self._persist_ticketing_fields(
            tenant_id,
            {
                "project_type": "jsm",
                "jsm_service_desk_id": service_desk_id,
            },
        )

        return tenant_secrets.model_copy(
            update={
                "project_type": "jsm",
                "jsm_service_desk_id": service_desk_id,
            }
        )
