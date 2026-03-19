"""shared.models.chatops - ChatOps message contracts and provider interface.

This module provides normalized message and action schemas that can be mapped
to multiple chat platforms (for example, Microsoft Teams Adaptive Cards and
Slack Block Kit) without leaking provider-specific structures into activities
or workflows.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class ChatOpsAction(BaseModel):
    """Represents one interactive action rendered by a ChatOps platform.

    Attributes:
        action_id: Stable machine-readable action identifier.
        label: Human-readable button label.
        style: Optional visual hint for platform-specific rendering.
        payload: Hidden metadata posted back by the platform on interaction.
        requires_confirmation: Indicates whether UI should request confirmation.
    """

    model_config = ConfigDict(from_attributes=True)

    action_id: str
    label: str
    style: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    requires_confirmation: bool = False


class ChatOpsMessage(BaseModel):
    """Provider-agnostic message payload used for outbound ChatOps alerts.

    Attributes:
        title: Message title shown prominently in the chat client.
        body: Main message body with incident context.
        actions: Optional interactive actions (buttons) for remediation choices.
        metadata: Additional key-value metadata for rendering or tracing.
    """

    model_config = ConfigDict(from_attributes=True)

    title: str
    body: str
    actions: list[ChatOpsAction] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


@runtime_checkable
class ChatOpsProvider(Protocol):
    """Provider contract for ChatOps transport and webhook verification.

    Implementations are responsible for converting normalized message payloads
    into platform-native format and validating callback authenticity.
    """

    async def send_message(self, target_channel: str, message: ChatOpsMessage) -> str:
        """Send a message to the target channel and return provider message id."""

    async def validate_webhook_signature(self, headers: dict[str, str], body: bytes) -> bool:
        """Validate inbound webhook signature and return True when trusted."""
