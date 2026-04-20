from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx

from connectors.errors import ConnectorPermanentError, ConnectorTransientError
from shared.graph_client import get_defender_token, get_graph_token
from shared.providers.contracts import TenantSecrets


@dataclass(frozen=True)
class MicrosoftTransportConfig:
    max_attempts: int = 3
    timeout_seconds: float = 20.0


class MicrosoftApiTransport:
    """Shared HTTP transport with token loading and bounded retry logic."""

    def __init__(self, *, secrets: TenantSecrets, config: MicrosoftTransportConfig | None = None) -> None:
        self._secrets = secrets
        self._config = config or MicrosoftTransportConfig()

    @staticmethod
    def _retry_delay_seconds(retry_after_header: str | None, attempt: int) -> float:
        if retry_after_header:
            try:
                return max(0.0, float(retry_after_header))
            except ValueError:
                pass
        return float(min(2 ** (attempt - 1), 30))

    @staticmethod
    def _graph_error_details(response: httpx.Response) -> str:
        try:
            body = response.json()
        except ValueError:
            return ""
        if not isinstance(body, dict):
            return ""

        error = body.get("error")
        if not isinstance(error, dict):
            return ""

        code = str(error.get("code") or "").strip()
        message = str(error.get("message") or "").strip()
        parts: list[str] = []
        if code:
            parts.append(f"code={code}")
        if message:
            parts.append(f"message={message}")
        return f" ({', '.join(parts)})" if parts else ""

    async def _request_with_retry(
        self,
        method: str,
        url: str,
        *,
        token: str,
        params: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
    ) -> httpx.Response:
        headers = {"Authorization": f"Bearer {token}"}
        last_error: Exception | None = None

        for attempt in range(1, self._config.max_attempts + 1):
            try:
                async with httpx.AsyncClient(timeout=self._config.timeout_seconds) as client:
                    response = await client.request(
                        method=method,
                        url=url,
                        headers=headers,
                        params=params,
                        json=json,
                    )
            except httpx.RequestError as exc:
                last_error = exc
                if attempt == self._config.max_attempts:
                    break
                await asyncio.sleep(self._retry_delay_seconds(None, attempt))
                continue

            if response.status_code in (429, 503):
                if attempt == self._config.max_attempts:
                    raise ConnectorTransientError(
                        f"Microsoft API throttled/unavailable after retries: status={response.status_code} url={url}"
                    )
                await asyncio.sleep(self._retry_delay_seconds(response.headers.get("Retry-After"), attempt))
                continue

            if response.status_code in (400, 401, 403, 404):
                error_details = self._graph_error_details(response)
                raise ConnectorPermanentError(
                    f"Microsoft API request rejected: status={response.status_code} url={url}{error_details}"
                )

            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                if 500 <= response.status_code < 600:
                    last_error = exc
                    if attempt == self._config.max_attempts:
                        break
                    await asyncio.sleep(self._retry_delay_seconds(response.headers.get("Retry-After"), attempt))
                    continue
                error_details = self._graph_error_details(response)
                raise ConnectorPermanentError(
                    f"Microsoft API request failed: status={response.status_code} url={url}{error_details}"
                ) from exc

            return response

        raise ConnectorTransientError(f"Microsoft API request failed after retries: {url}") from last_error

    async def request_graph(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
    ) -> httpx.Response:
        token = await get_graph_token(self._secrets)
        return await self._request_with_retry(method, url, token=token, params=params, json=json)

    async def request_defender(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
    ) -> httpx.Response:
        token = await get_defender_token(self._secrets)
        return await self._request_with_retry(method, url, token=token, params=params, json=json)
