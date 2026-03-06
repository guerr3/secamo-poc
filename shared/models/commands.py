"""
shared.models.commands — Workflow command models.

Represent the intent to start or signal a Temporal workflow,
generated from a CanonicalEvent by the mapper layer.
"""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict


class WorkflowCommand(BaseModel):
    """Base class for workflow commands."""
    model_config = ConfigDict(extra="ignore")

    tenant_id: str
    command_type: Literal["start_workflow", "signal_workflow"]


class StartWorkflowCommand(WorkflowCommand):
    """Command to start a new Temporal workflow."""

    command_type: Literal["start_workflow"] = "start_workflow"
    workflow_name: str
    workflow_id: Optional[str] = None
    task_queue: str
    workflow_input: dict[str, Any]


class SignalWorkflowCommand(WorkflowCommand):
    """Command to signal a running Temporal workflow."""

    command_type: Literal["signal_workflow"] = "signal_workflow"
    workflow_id: str
    signal_name: str
    signal_payload: dict[str, Any]
