"""Phase-4 verification for approval callback normalization.

Responsibility: verify all callback channels normalize into ApprovalSignal and preserve additive action semantics at payload level.
This module must not test auth signature verification or workflow execution internals.
"""

from __future__ import annotations

from shared.approval.callbacks import normalize_approval_callback


def test_callback_matrix_normalizes_to_same_signal_shape() -> None:
    expected_keys = {"signal_type", "approved", "action", "actor", "comments"}

    email_signal = normalize_approval_callback(
        "email",
        {"action": "approve", "actor": "email:analyst@example.com", "comments": "email ok"},
    )
    jira_signal = normalize_approval_callback(
        "jira",
        {"status": "approved", "action": "approve", "actor": "jira:SEC-101", "comments": "jira ok"},
    )
    slack_signal = normalize_approval_callback(
        "slack",
        {"action": "approve", "actor": "slack:U123", "comments": "slack ok"},
    )
    teams_signal = normalize_approval_callback(
        "teams",
        {"action": "approve", "actor": "teams:42", "comments": "teams ok"},
    )

    for signal in [email_signal, jira_signal, slack_signal, teams_signal]:
        payload = signal.model_dump(mode="json")
        assert set(payload.keys()) == expected_keys
        assert payload["signal_type"] == "approval"
        assert payload["action"] == "approve"
        assert payload["approved"] is True


def test_callback_rejects_unsupported_channel() -> None:
    try:
        normalize_approval_callback("pagerduty", {"actor": "pd:1"})
    except ValueError as exc:
        assert "unsupported_channel" in str(exc)
    else:
        raise AssertionError("Expected ValueError for unsupported channel")


def test_callback_supports_additive_action_values_without_contract_changes() -> None:
    signal = normalize_approval_callback(
        "teams",
        {"action": "disable_user", "actor": "teams:42", "comments": "extended action"},
    )
    assert signal.action == "disable_user"
    assert signal.actor == "teams:42"
