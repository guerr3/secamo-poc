from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs

from fastapi import APIRouter, HTTPException, Request
from temporalio.client import Client
from temporalio.contrib.pydantic import pydantic_data_converter

from shared.config import TEMPORAL_ADDRESS, TEMPORAL_NAMESPACE
from shared.providers.factory import get_chatops_provider, get_tenant_runtime_config
from shared.ssm_client import get_secret_bundle


router = APIRouter()


@dataclass(frozen=True)
class ChatOpsActionEnvelope:
    """Normalized action envelope extracted from provider callback payload."""

    tenant_id: str
    workflow_id: str
    run_id: str
    action_taken: str
    actor: str
    platform: str
    raw_payload: dict[str, Any]


class TemporalChatOpsSignalDispatcher:
    """Dispatch ChatOps action signals to running workflows."""

    def __init__(self) -> None:
        self._client: Client | None = None

    async def _get_client(self) -> Client:
        if self._client is None:
            self._client = await Client.connect(
                TEMPORAL_ADDRESS,
                namespace=TEMPORAL_NAMESPACE,
                data_converter=pydantic_data_converter,
            )
        return self._client

    async def signal_chatops_action(self, envelope: ChatOpsActionEnvelope) -> None:
        """Signal a target workflow execution with normalized action metadata."""
        client = await self._get_client()
        handle = client.get_workflow_handle(envelope.workflow_id, run_id=envelope.run_id)
        await handle.signal(
            "chatops_action_received",
            {
                "tenant_id": envelope.tenant_id,
                "workflow_id": envelope.workflow_id,
                "run_id": envelope.run_id,
                "action_taken": envelope.action_taken,
                "actor": envelope.actor,
                "platform": envelope.platform,
                "received_at": datetime.now(timezone.utc).isoformat(),
                "raw_payload": envelope.raw_payload,
            },
        )


_dispatcher = TemporalChatOpsSignalDispatcher()


def _headers_as_dict(request: Request) -> dict[str, str]:
    """Convert FastAPI headers into a plain case-preserving dictionary."""
    return {str(k): str(v) for k, v in request.headers.items()}


def _detect_platform(headers: dict[str, str], raw_body: bytes) -> str:
    """Detect callback source platform from headers/body hints."""
    normalized = {k.lower(): v for k, v in headers.items()}
    if "x-slack-signature" in normalized:
        return "slack"
    if "payload=" in raw_body.decode("utf-8", errors="ignore"):
        return "slack"
    return "ms_teams"


def _extract_slack_payload(raw_body: bytes) -> dict[str, Any]:
    """Extract Slack callback payload from JSON or form-encoded request body."""
    decoded = raw_body.decode("utf-8")

    try:
        direct = json.loads(decoded)
        if isinstance(direct, dict):
            return direct
    except json.JSONDecodeError:
        pass

    parsed_qs = parse_qs(decoded, keep_blank_values=True)
    payload_values = parsed_qs.get("payload", [])
    if not payload_values:
        raise ValueError("Slack callback missing payload field")

    payload = json.loads(payload_values[0])
    if not isinstance(payload, dict):
        raise ValueError("Slack payload must be a JSON object")
    return payload


def _extract_teams_payload(raw_body: bytes) -> dict[str, Any]:
    """Extract Teams callback payload from JSON request body."""
    decoded = raw_body.decode("utf-8")
    parsed = json.loads(decoded)
    if not isinstance(parsed, dict):
        raise ValueError("Teams callback payload must be a JSON object")
    return parsed


def _required_str(data: dict[str, Any], key: str) -> str:
    """Return a required string field or raise a descriptive validation error."""
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Missing required field '{key}'")
    return value.strip()


def _normalize_action_envelope(platform: str, payload: dict[str, Any]) -> ChatOpsActionEnvelope:
    """Normalize provider-specific callback payload into one common shape."""
    if platform == "slack":
        user_name = "unknown-user"
        user_obj = payload.get("user")
        if isinstance(user_obj, dict):
            user_name = str(user_obj.get("username") or user_obj.get("name") or user_obj.get("id") or user_name)

        actions = payload.get("actions")
        if not isinstance(actions, list) or not actions:
            raise ValueError("Slack payload missing actions")
        first_action = actions[0] if isinstance(actions[0], dict) else {}

        action_taken = str(first_action.get("action_id") or "").strip()
        if not action_taken:
            raise ValueError("Slack action_id missing")

        value_payload: dict[str, Any] = {}
        raw_value = first_action.get("value")
        if isinstance(raw_value, str) and raw_value.strip():
            try:
                parsed_value = json.loads(raw_value)
                if isinstance(parsed_value, dict):
                    value_payload = parsed_value
            except json.JSONDecodeError:
                value_payload = {}

        tenant_id = _required_str(value_payload, "tenant_id")
        workflow_id = _required_str(value_payload, "workflow_id")
        run_id = _required_str(value_payload, "run_id")

        return ChatOpsActionEnvelope(
            tenant_id=tenant_id,
            workflow_id=workflow_id,
            run_id=run_id,
            action_taken=action_taken,
            actor=user_name,
            platform=platform,
            raw_payload=payload,
        )

    # Teams payloads should carry hidden data in action data field.
    data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    tenant_id = _required_str(data, "tenant_id")
    workflow_id = _required_str(data, "workflow_id")
    run_id = _required_str(data, "run_id")
    action_taken = _required_str(data, "action_taken")

    actor = "unknown-user"
    from_obj = payload.get("from")
    if isinstance(from_obj, dict):
        actor = str(from_obj.get("name") or from_obj.get("id") or actor)

    return ChatOpsActionEnvelope(
        tenant_id=tenant_id,
        workflow_id=workflow_id,
        run_id=run_id,
        action_taken=action_taken,
        actor=actor,
        platform=platform,
        raw_payload=payload,
    )


def _secret_type_from_credentials_path(path_template: str) -> str:
    """Extract SSM secret_type from a configured credentials path template."""
    normalized = path_template.replace("{tenant_id}", "tenant-placeholder").strip("/")
    parts = [part for part in normalized.split("/") if part]
    if not parts:
        return "chatops"
    return parts[-1]


async def _load_secret_bundle_async(tenant_id: str, secret_type: str) -> dict[str, str]:
    """Load tenant secret bundle via thread offloading for boto3-backed calls."""
    return await asyncio.to_thread(get_secret_bundle, tenant_id, secret_type)


def _success_response(platform: str, action_taken: str, actor: str) -> dict[str, Any]:
    """Build provider-specific success response payload."""
    if platform == "slack":
        return {
            "response_type": "ephemeral",
            "replace_original": False,
            "text": f"Action Executed by {actor}: {action_taken}",
        }

    return {
        "statusCode": 200,
        "type": "application/vnd.microsoft.activity.message",
        "value": f"Action Executed by {actor}: {action_taken}",
    }


@router.post("/chatops/action")
async def receive_chatops_action(request: Request) -> dict[str, Any]:
    """Receive ChatOps action callbacks and signal target workflow execution.

    Flow:
    1. Parse payload for routing metadata.
    2. Resolve tenant provider and validate webhook signature.
    3. Extract workflow_id/run_id/action_taken.
    4. Signal Temporal workflow with ``chatops_action_received``.
    5. Return platform-appropriate callback response payload.
    """
    raw_body = await request.body()
    headers = _headers_as_dict(request)
    platform = _detect_platform(headers, raw_body)

    try:
        untrusted_payload = _extract_slack_payload(raw_body) if platform == "slack" else _extract_teams_payload(raw_body)
        envelope = _normalize_action_envelope(platform, untrusted_payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    tenant_cfg = await get_tenant_runtime_config(envelope.tenant_id)
    secret_type = _secret_type_from_credentials_path(tenant_cfg.chatops_config.credentials_path)
    secrets = await _load_secret_bundle_async(envelope.tenant_id, secret_type)
    provider = await get_chatops_provider(envelope.tenant_id, secrets)

    is_valid = await provider.validate_webhook_signature(headers=headers, body=raw_body)
    if not is_valid:
        raise HTTPException(status_code=401, detail="Invalid ChatOps webhook signature")

    await _dispatcher.signal_chatops_action(envelope)
    return _success_response(envelope.platform, envelope.action_taken, envelope.actor)
