"""shared.models.triage - AI triage contracts and provider interface.

This module defines provider-agnostic data contracts used by activities,
workflows, and provider implementations involved in AI-driven security triage.
All structures are intentionally generic so they can be shared across Azure
OpenAI, AWS Bedrock, and local model providers without branching logic in
workflow or activity code.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class TriageRequest(BaseModel):
    """Canonical request payload for AI triage analysis.

    Attributes:
        tenant_id: Tenant identifier used for multi-tenant routing and policy.
        alert_id: Optional provider-native alert identifier for traceability.
        alert_data: Raw or normalized alert payload to analyze.
        context: Optional supplemental context to improve triage quality.
    """

    model_config = ConfigDict(from_attributes=True)

    tenant_id: str
    alert_id: str | None = None
    alert_data: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] = Field(default_factory=dict)


class TriageResult(BaseModel):
    """Canonical output contract returned by an AI triage provider.

    Attributes:
        confidence_score: Model confidence in the recommendation, from 0 to 1.
        summary: Human-readable triage summary suitable for analyst review.
        recommended_actions: Ordered list of suggested remediation actions.
        is_false_positive: Indicates whether the alert is likely benign.
    """

    model_config = ConfigDict(from_attributes=True)

    confidence_score: float = Field(ge=0.0, le=1.0)
    summary: str
    recommended_actions: list[str] = Field(default_factory=list)
    is_false_positive: bool


@runtime_checkable
class AITriageProvider(Protocol):
    """Provider contract for asynchronous AI triage implementations.

    Implementations encapsulate provider-specific API behavior while exposing
    a stable interface that activities can call without coupling to any one
    model vendor.
    """

    async def analyze_alert(self, request: TriageRequest) -> TriageResult:
        """Analyze a security alert and return a normalized triage result."""
