"""Ingress fan-out dispatcher abstractions for workflow start operations.

Responsibility: bridge Envelope and WorkflowRoute dispatch using a transport-agnostic workflow starter.
This module must not parse provider payloads or contain endpoint handler logic.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from shared.models import SecurityCaseInput
from shared.models.canonical import DefenderSecuritySignalEvent
from shared.normalization.iam.onboarding_event import normalize_iam_onboarding_case
from shared.normalization.soc import (
    normalize_audit_log_case,
    normalize_defender_alert_case,
    normalize_impossible_travel_case,
    normalize_noncompliant_device_case,
    normalize_risky_user_case,
    normalize_signin_log_case,
)
from shared.models.canonical import Envelope
from shared.routing.contracts import DispatchReport, WorkflowRoute
from shared.routing.registry import RouteDispatcher, RouteRegistry


_SOC_SIGNAL_NORMALIZERS = {
    "SigninAnomalyDetectionWorkflow": normalize_signin_log_case,
    "RiskyUserTriageWorkflow": normalize_risky_user_case,
    "DeviceComplianceRemediationWorkflow": normalize_noncompliant_device_case,
    "AuditLogAnomalyWorkflow": normalize_audit_log_case,
}


def _safe_severity(value: str | None, default: str) -> str:
    normalized = str(value or default).strip().lower() or default
    return normalized if normalized in {"low", "medium", "high", "critical"} else default


def _vendor_string(payload: object, key: str) -> str | None:
    vendor_extensions = getattr(payload, "vendor_extensions", None)
    if not isinstance(vendor_extensions, dict):
        return None

    extension = vendor_extensions.get(key)
    if extension is None:
        return None

    value = getattr(extension, "value", None)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _soc_alert_case_input(envelope: Envelope) -> SecurityCaseInput:
    if envelope.payload.event_type == "defender.alert":
        return normalize_defender_alert_case(envelope, auto_remediate=False)

    if envelope.payload.event_type == "defender.impossible_travel":
        return normalize_impossible_travel_case(envelope, auto_remediate=False)

    payload = envelope.payload
    if isinstance(payload, DefenderSecuritySignalEvent):
        return SecurityCaseInput(
            tenant_id=envelope.tenant_id,
            case_type="generic_signal",
            severity=_safe_severity(payload.severity, "medium"),
            alert_id=payload.signal_id,
            allowed_actions=["dismiss", "isolate", "disable_user"],
            auto_remediate=False,
            identity=_vendor_string(payload, "user_email"),
            device=_vendor_string(payload, "device_id"),
            source_event=envelope,
        )

    raise ValueError(
        "SocAlertTriageWorkflow requires defender.alert, impossible_travel, or security_signal payload"
    )


def workflow_input_for_route(
    route: WorkflowRoute,
    envelope: Envelope,
    *,
    envelope_fallback_as_dict: bool = True,
) -> dict[str, Any] | Envelope:
    """Shape routed workflow input using shared ingress normalization rules."""

    if route.workflow_name == "IamOnboardingWorkflow":
        case_input = normalize_iam_onboarding_case(envelope)
        return case_input.model_dump(mode="json")

    if route.workflow_name == "SocAlertTriageWorkflow":
        case_input = _soc_alert_case_input(envelope)
        return case_input.model_dump(mode="json")

    normalizer = _SOC_SIGNAL_NORMALIZERS.get(route.workflow_name)
    if normalizer is not None:
        case_input = normalizer(envelope, auto_remediate=False)
        return case_input.model_dump(mode="json")

    if envelope_fallback_as_dict:
        return envelope.model_dump(mode="json")
    return envelope


@runtime_checkable
class WorkflowStarter(Protocol):
    """Protocol for starting workflows from routed ingress envelopes."""

    async def start(
        self,
        *,
        workflow_name: str,
        workflow_input: dict[str, Any],
        task_queue: str,
        tenant_id: str,
        workflow_id: str,
    ) -> Any:
        """Start one workflow execution for the provided route and input payload."""


class _WorkflowRouteDispatcher(RouteDispatcher):
    """Route dispatcher adapter that delegates route starts to WorkflowStarter."""

    def __init__(self, starter: WorkflowStarter) -> None:
        self._starter = starter

    @staticmethod
    def _workflow_input_for_route(route: WorkflowRoute, envelope: Envelope) -> dict[str, Any]:
        return workflow_input_for_route(route, envelope, envelope_fallback_as_dict=True)

    async def dispatch(self, route: WorkflowRoute, envelope: Envelope) -> None:
        workflow_input = self._workflow_input_for_route(route, envelope)
        workflow_id = (
            f"ingress-{envelope.tenant_id}-{route.workflow_name}-{envelope.payload.event_type}-{envelope.event_id}"
        )
        await self._starter.start(
            workflow_name=route.workflow_name,
            workflow_input=workflow_input,
            task_queue=route.task_queue,
            tenant_id=envelope.tenant_id,
            workflow_id=workflow_id,
        )


class RouteFanoutDispatcher:
    """Best-effort fan-out dispatcher using shared route registry semantics."""

    def __init__(self, route_registry: RouteRegistry, workflow_starter: WorkflowStarter) -> None:
        self._route_registry = route_registry
        self._dispatcher = _WorkflowRouteDispatcher(workflow_starter)

    async def dispatch_intent(self, envelope: Envelope) -> DispatchReport:
        """Dispatch one Envelope across all matching WorkflowRoute entries."""

        return await self._route_registry.dispatch_best_effort(envelope, self._dispatcher)
