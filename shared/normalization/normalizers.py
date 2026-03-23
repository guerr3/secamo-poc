"""Canonical-to-intent normalization helpers.

Responsibility: convert canonical events into WorkflowIntent contracts for routing/dispatch.
This module must not contain transport endpoint handlers or Temporal SDK imports.
"""

from __future__ import annotations

from typing import Any

from shared.models.canonical import CanonicalEvent
from shared.normalization.contracts import WorkflowIntent


def canonical_event_to_workflow_intent(
    canonical_event: CanonicalEvent,
    *,
    workflow_input: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> WorkflowIntent:
    """Convert a canonical event into the public WorkflowIntent boundary model."""

    meta = {} if metadata is None else dict(metadata)
    if canonical_event.request_id:
        meta.setdefault("request_id", canonical_event.request_id)
    if canonical_event.correlation_id:
        meta.setdefault("correlation_id", canonical_event.correlation_id)

    payload = {
        "workflow_input": workflow_input if workflow_input is not None else dict(canonical_event.payload),
    }

    return WorkflowIntent(
        tenant_id=canonical_event.tenant_id,
        provider=canonical_event.provider,
        event_type=canonical_event.event_type,
        intent_type="workflow.start",
        payload=payload,
        metadata=meta,
    )
