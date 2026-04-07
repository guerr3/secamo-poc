from __future__ import annotations

import asyncio
import base64
import ipaddress
from typing import Any
from urllib.parse import quote

import httpx

from connectors.base import BaseConnector
from connectors.errors import (
    ConnectorConfigurationError,
    ConnectorPermanentError,
    ConnectorTransientError,
    ConnectorUnsupportedActionError,
)


class VirusTotalConnector(BaseConnector):
    """VirusTotal connector for indicator reputation lookups."""

    _BASE_URL = "https://www.virustotal.com/api/v3"
    _MAX_ATTEMPTS = 3

    @property
    def provider(self) -> str:
        return "virustotal"

    def _api_key(self) -> str:
        api_key = (self.secrets.virustotal_api_key or "").strip()
        if not api_key:
            raise ConnectorConfigurationError("Missing virustotal_api_key in tenant secrets")
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

    @staticmethod
    def _indicator_type(indicator: str) -> str:
        try:
            ipaddress.ip_address(indicator)
            return "ip"
        except ValueError:
            pass

        if indicator.startswith("http://") or indicator.startswith("https://"):
            return "url"

        lowered = indicator.lower()
        if len(lowered) in {32, 40, 64} and all(ch in "0123456789abcdef" for ch in lowered):
            return "file"

        return "domain"

    @staticmethod
    def _url_id(url: str) -> str:
        return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")

    async def _request_with_retry(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        timeout: float = 20.0,
        allow_not_found: bool = False,
    ) -> httpx.Response:
        headers = {
            "x-apikey": self._api_key(),
            "accept": "application/json",
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
                        f"VirusTotal throttled/unavailable after retries: status={response.status_code} url={url}"
                    )
                await asyncio.sleep(self._retry_delay_seconds(response.headers.get("Retry-After"), attempt))
                continue

            if response.status_code == 404 and allow_not_found:
                return response

            if response.status_code in (400, 401, 403, 404):
                raise ConnectorPermanentError(
                    f"VirusTotal request rejected: status={response.status_code} url={url}"
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
                    f"VirusTotal request failed: status={response.status_code} url={url}"
                ) from exc

            return response

        raise ConnectorTransientError(f"VirusTotal request failed after retries: {url}") from last_error

    @classmethod
    def _score_from_stats(cls, stats: dict[str, Any]) -> float:
        malicious_votes = cls._as_int(stats.get("malicious")) + cls._as_int(stats.get("suspicious"))
        total_votes = max(sum(cls._as_int(value) for value in stats.values()), 1)
        return round(min((malicious_votes / total_votes) * 100.0, 100.0), 2)

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

        indicator_type = self._indicator_type(indicator)
        if indicator_type == "ip":
            path = f"/ip_addresses/{quote(indicator)}"
        elif indicator_type == "url":
            path = f"/urls/{quote(self._url_id(indicator))}"
        elif indicator_type == "file":
            path = f"/files/{quote(indicator.lower())}"
        else:
            path = f"/domains/{quote(indicator.lower())}"

        response = await self._request_with_retry(
            "GET",
            f"{self._BASE_URL}{path}",
            allow_not_found=True,
        )

        if response.status_code == 404:
            return {
                "success": True,
                "provider": self.provider,
                "indicator": indicator,
                "is_malicious": False,
                "reputation_score": 0.0,
                "details": "indicator not found",
            }

        attrs = (response.json().get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        score = self._score_from_stats(stats if isinstance(stats, dict) else {})
        malicious_threshold = float(payload.get("malicious_threshold") or 20.0)

        return {
            "success": True,
            "provider": self.provider,
            "indicator": indicator,
            "is_malicious": score >= malicious_threshold,
            "reputation_score": score,
            "details": f"VirusTotal lookup ({indicator_type})",
            "stats": stats,
        }

    async def health_check(self) -> dict:
        response = await self._request_with_retry(
            "GET",
            f"{self._BASE_URL}/ip_addresses/8.8.8.8",
            allow_not_found=True,
            timeout=15.0,
        )
        return {
            "healthy": response.status_code in {200, 404},
            "status_code": response.status_code,
            "provider": self.provider,
        }
