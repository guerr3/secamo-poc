"""Azure OpenAI provider for tenant-scoped AI triage.

This module implements :class:`shared.providers.protocols.AITriageProvider` and keeps
all vendor-specific behavior encapsulated behind the protocol boundary.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from shared.models import TriageRequest, TriageResult


class AzureOpenAITriageProvider:
    """Azure OpenAI-backed implementation of AI triage analysis.

    The provider redacts common PII patterns before sending request content to
    the model. It requests a strict JSON response that maps directly to
    :class:`TriageResult`.
    """

    _EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    _IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _PHONE_RE = re.compile(r"\b\+?\d[\d\s().-]{7,}\d\b")

    def __init__(
        self,
        *,
        endpoint: str,
        api_key: str,
        deployment_id: str,
        api_version: str = "2024-10-21",
        temperature: float = 0.0,
        max_tokens: int = 512,
        timeout_seconds: float = 30.0,
    ) -> None:
        """Initialize an Azure OpenAI triage provider.

        Args:
            endpoint: Azure OpenAI resource endpoint.
            api_key: API key for the Azure OpenAI resource.
            deployment_id: Model deployment identifier.
            api_version: REST API version query parameter.
            temperature: Sampling temperature for model output.
            max_tokens: Maximum completion token budget.
            timeout_seconds: HTTP timeout in seconds.
        """

        self._endpoint = endpoint.rstrip("/")
        self._api_key = api_key
        self._deployment_id = deployment_id
        self._api_version = api_version
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._timeout_seconds = timeout_seconds

    @classmethod
    def _redact_pii_text(cls, value: str) -> str:
        """Redact common sensitive patterns from a string payload."""
        value = cls._EMAIL_RE.sub("[REDACTED_EMAIL]", value)
        value = cls._IPV4_RE.sub("[REDACTED_IP]", value)
        value = cls._PHONE_RE.sub("[REDACTED_PHONE]", value)
        return value

    @classmethod
    def _sanitize_object(cls, value: Any) -> Any:
        """Recursively sanitize primitive fields before LLM submission."""
        if isinstance(value, dict):
            return {str(k): cls._sanitize_object(v) for k, v in value.items()}
        if isinstance(value, list):
            return [cls._sanitize_object(item) for item in value]
        if isinstance(value, str):
            return cls._redact_pii_text(value)
        return value

    def _build_url(self) -> str:
        """Build the Azure OpenAI chat completions endpoint URL."""
        return (
            f"{self._endpoint}/openai/deployments/{self._deployment_id}/chat/completions"
            f"?api-version={self._api_version}"
        )

    @staticmethod
    def _extract_text_from_response(body: dict[str, Any]) -> str:
        """Extract assistant text content from an Azure OpenAI response body."""
        choices = body.get("choices", [])
        if not choices:
            raise RuntimeError("Azure OpenAI response contained no choices")

        first_choice = choices[0] if isinstance(choices[0], dict) else {}
        message = first_choice.get("message", {}) if isinstance(first_choice, dict) else {}
        content = message.get("content", "") if isinstance(message, dict) else ""
        if not isinstance(content, str) or not content.strip():
            raise RuntimeError("Azure OpenAI response did not include assistant content")
        return content.strip()

    @staticmethod
    def _parse_triage_response(content: str) -> TriageResult:
        """Parse and validate JSON model output into a canonical triage result."""
        # Some providers wrap JSON in markdown code fences; strip them defensively.
        normalized = content.strip()
        if normalized.startswith("```"):
            normalized = normalized.strip("`")
            normalized = normalized.replace("json", "", 1).strip()

        parsed = json.loads(normalized)
        if not isinstance(parsed, dict):
            raise RuntimeError("Triage model output must be a JSON object")

        result = TriageResult(
            confidence_score=float(parsed.get("confidence_score", 0.0)),
            summary=str(parsed.get("summary", "")),
            recommended_actions=[str(item) for item in parsed.get("recommended_actions", [])],
            is_false_positive=bool(parsed.get("is_false_positive", False)),
        )
        return result

    async def analyze_alert(self, request: TriageRequest) -> TriageResult:
        """Analyze alert context with Azure OpenAI and return normalized output.

        The request is sanitized for basic PII before submission.
        """

        sanitized_payload = self._sanitize_object(request.model_dump(mode="json"))

        prompt = (
            "You are a SOC triage assistant. Analyze the provided alert payload and "
            "return strict JSON with keys: confidence_score (0..1), summary, "
            "recommended_actions (array of strings), is_false_positive (boolean). "
            "Do not include markdown or additional commentary."
        )

        request_body: dict[str, Any] = {
            "temperature": self._temperature,
            "max_tokens": self._max_tokens,
            "messages": [
                {"role": "system", "content": prompt},
                {"role": "user", "content": json.dumps(sanitized_payload, ensure_ascii=True)},
            ],
        }

        headers = {
            "api-key": self._api_key,
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
            response = await client.post(self._build_url(), headers=headers, json=request_body)

        if response.status_code >= 400:
            raise RuntimeError(f"Azure OpenAI triage request failed with status={response.status_code}")

        response_body = response.json()
        content = self._extract_text_from_response(response_body)
        return self._parse_triage_response(content)
