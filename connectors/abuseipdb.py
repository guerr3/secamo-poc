from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

import httpx

from connectors.base import BaseConnector
from connectors.errors import (
    ConnectorConfigurationError,
    ConnectorPermanentError,
    ConnectorTransientError,
    ConnectorUnsupportedActionError,
)


class AbuseIpdbConnector(BaseConnector):
    """AbuseIPDB connector for IP reputation lookups."""

    _BASE_URL = "https://api.abuseipdb.com/api/v2"
    _MAX_ATTEMPTS = 3

    @property
    def provider(self) -> str:
        return "abuseipdb"

    def _api_key(self) -> str:
        api_key = (self.secrets.abuseipdb_api_key or "").strip()
        if not api_key:
            raise ConnectorConfigurationError("Missing abuseipdb_api_key in tenant secrets")
        return api_key

    @staticmethod
    def _retry_delay_seconds(retry_after_header: str | None, attempt: int) -> float:
        if retry_after_header:
            try:
                return max(0.0, float(retry_after_header))
            except ValueError:
                pass
        return float(min(2 ** (attempt - 1), 30))

    @staticmethod
    def _as_int(value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    async def _request_with_retry(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        timeout: float = 20.0,
    ) -> httpx.Response:
        headers = {
            "Key": self._api_key(),
            "Accept": "application/json",
        }
        last_error: Exception | None = None

        for attempt in range(1, self._MAX_ATTEMPTS + 1):
            try:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    response = await client.request(method=method, url=url, headers=headers, params=params)
            except httpx.RequestError as exc:
                last_error = exc
                if attempt == self._MAX_ATTEMPTS:
                    break
                await asyncio.sleep(self._retry_delay_seconds(None, attempt))
                continue

            if response.status_code in (429, 503, 504):
                if attempt == self._MAX_ATTEMPTS:
                    raise ConnectorTransientError(
                        f"AbuseIPDB throttled/unavailable after retries: status={response.status_code} url={url}"
                    )
                await asyncio.sleep(self._retry_delay_seconds(response.headers.get("Retry-After"), attempt))
                continue

            if response.status_code in (400, 401, 403, 404, 422):
                raise ConnectorPermanentError(
                    f"AbuseIPDB request rejected: status={response.status_code} url={url}"
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
                    f"AbuseIPDB request failed: status={response.status_code} url={url}"
                ) from exc

            return response

        raise ConnectorTransientError(f"AbuseIPDB request failed after retries: {url}") from last_error

    async def fetch_events(self, query: dict) -> list:
        _ = query
        return []

    async def execute_action(self, action: str, payload: dict) -> dict:
        if action != "lookup_indicator":
            raise ConnectorUnsupportedActionError(
                f"Unsupported action '{action}' for provider '{self.provider}'"
            )

        indicator = str(payload.get("indicator") or "").strip()
        if not indicator:
            raise ConnectorPermanentError("lookup_indicator requires payload.indicator")

        try:
            parsed_ip = ipaddress.ip_address(indicator)
        except ValueError as exc:
            raise ConnectorPermanentError("AbuseIPDB supports IP indicators only") from exc

        max_age_days = min(max(self._as_int(payload.get("max_age_days"), default=90), 1), 365)
        malicious_threshold = float(payload.get("malicious_threshold") or 25.0)
        verbose = bool(payload.get("verbose", False))

        params = {
            "ipAddress": str(parsed_ip),
            "maxAgeInDays": str(max_age_days),
        }
        if verbose:
            params["verbose"] = ""

        response = await self._request_with_retry("GET", f"{self._BASE_URL}/check", params=params)
        data = response.json().get("data") or {}
        score = float(data.get("abuseConfidenceScore") or 0.0)

        return {
            "success": True,
            "provider": self.provider,
            "indicator": str(parsed_ip),
            "is_malicious": score >= malicious_threshold,
            "reputation_score": round(score, 2),
            "details": (
                f"AbuseIPDB check totalReports={self._as_int(data.get('totalReports'))} "
                f"country={data.get('countryCode') or 'unknown'}"
            ),
            "total_reports": self._as_int(data.get("totalReports")),
        }

    async def health_check(self) -> dict:
        response = await self._request_with_retry(
            "GET",
            f"{self._BASE_URL}/check",
            params={"ipAddress": "8.8.8.8", "maxAgeInDays": "30"},
            timeout=15.0,
        )
        return {
            "healthy": response.status_code == 200,
            "status_code": response.status_code,
            "provider": self.provider,
        }
