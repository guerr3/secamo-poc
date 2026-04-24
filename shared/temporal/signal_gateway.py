"""Signal gateway abstraction for workflow signal dispatch.

Responsibility: map typed signal payloads to signal names and dispatch through a transport protocol.
This module must not import Temporal SDK directly or perform provider-specific parsing.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from shared.approval.callbacks import approval_signal_to_decision
from shared.approval.contracts import ApprovalSignal, GenericActionSignal, SignalPayload


@runtime_checkable
class SignalTransport(Protocol):
    """Transport interface for dispatching named workflow signals."""

    async def send(
        self,
        workflow_id: str,
        run_id: str | None,
        signal_name: str,
        payload: dict,
    ) -> None:
        """Send one named signal payload to a workflow execution target."""


class SignalGateway:
    """Typed signal gateway independent from transport implementation details."""

    def __init__(self, transport: SignalTransport) -> None:
        self._transport = transport

    @staticmethod
    def signal_name(payload: SignalPayload) -> str:
        """Resolve signal name from discriminated signal payload type."""

        if isinstance(payload, ApprovalSignal):
            return "approve"
        if isinstance(payload, GenericActionSignal):
            return "action"
        raise ValueError("unsupported_signal_payload")

    async def dispatch(self, workflow_id: str, payload: SignalPayload, run_id: str | None = None) -> None:
        """Dispatch typed signal payload through configured transport.

        ApprovalSignal payloads are converted to ApprovalDecision-compatible
        dicts so the inline workflow signal handler receives the expected
        field names (actor → reviewer).
        """
        if isinstance(payload, ApprovalSignal):
            decision = approval_signal_to_decision(payload)
            signal_payload = decision.model_dump(mode="json")
        else:
            signal_payload = payload.model_dump(mode="json")

        await self._transport.send(
            workflow_id=workflow_id,
            run_id=run_id,
            signal_name=self.signal_name(payload),
            payload=signal_payload,
        )
