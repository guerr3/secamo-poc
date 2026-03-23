"""Approval callback normalization utilities.

Responsibility: map channel-specific callback payloads to a shared ApprovalSignal contract.
This module must not perform signature validation, token persistence, or Temporal SDK dispatch.
"""

from __future__ import annotations

from typing import Any

from shared.approval.contracts import ApprovalSignal


def _required_text(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing_required_field:{key}")
    return value.strip()


def _approved_from_action(action: str) -> bool:
    normalized = action.strip().lower()
    return normalized not in {"dismiss", "deny", "reject"}


def _normalize_email(payload: dict[str, Any]) -> ApprovalSignal:
    action = str(payload.get("action") or "approve").strip() or "approve"
    actor = str(payload.get("actor") or payload.get("reviewer") or "email:unknown").strip() or "email:unknown"
    comments = str(payload.get("comments") or "").strip()
    return ApprovalSignal(
        approved=_approved_from_action(action),
        action=action,
        actor=actor,
        comments=comments,
    )


def _normalize_jira(payload: dict[str, Any]) -> ApprovalSignal:
    actor = str(payload.get("actor") or payload.get("reviewer") or "jira:unknown").strip() or "jira:unknown"
    status = str(payload.get("status") or "").strip().lower()
    action = str(payload.get("action") or "approve").strip() or "approve"
    comments = str(payload.get("comments") or "").strip()

    approved = status in {"approved", "resolved"} if status else _approved_from_action(action)
    return ApprovalSignal(
        approved=approved,
        action=action,
        actor=actor,
        comments=comments,
    )


def _normalize_slack(payload: dict[str, Any]) -> ApprovalSignal:
    actor = _required_text(payload, "actor")
    action = str(payload.get("action") or "approve").strip() or "approve"
    comments = str(payload.get("comments") or "").strip()
    return ApprovalSignal(
        approved=_approved_from_action(action),
        action=action,
        actor=actor,
        comments=comments,
    )


def _normalize_teams(payload: dict[str, Any]) -> ApprovalSignal:
    actor = _required_text(payload, "actor")
    action = str(payload.get("action") or "approve").strip() or "approve"
    comments = str(payload.get("comments") or "").strip()
    return ApprovalSignal(
        approved=_approved_from_action(action),
        action=action,
        actor=actor,
        comments=comments,
    )


def normalize_approval_callback(channel: str, payload: dict[str, Any]) -> ApprovalSignal:
    """Normalize channel-specific approval callback payload to ApprovalSignal."""

    normalized_channel = channel.strip().lower()
    if normalized_channel == "email":
        return _normalize_email(payload)
    if normalized_channel == "jira":
        return _normalize_jira(payload)
    if normalized_channel == "slack":
        return _normalize_slack(payload)
    if normalized_channel in {"teams", "ms_teams"}:
        return _normalize_teams(payload)
    raise ValueError(f"unsupported_channel:{channel}")
