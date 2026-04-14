from __future__ import annotations

import pytest
from temporalio.exceptions import ApplicationError

from activities.communications import email_send, teams_send_adaptive_card, teams_send_notification


@pytest.mark.asyncio
async def test_teams_send_notification_happy(mocker):
    provider = mocker.AsyncMock()
    provider.send_message.return_value = "m1"
    mocker.patch(
        "activities.communications._resolve_chatops_target",
        new=mocker.AsyncMock(return_value=(provider, "alerts")),
    )

    res = await teams_send_notification("t1", "https://example.webhook", "hello")
    assert res.success is True
    assert res.message_id == "m1"


@pytest.mark.asyncio
async def test_teams_send_notification_uses_configured_chatops_target(mocker):
    provider = mocker.AsyncMock()
    provider.send_message.return_value = "m2"
    resolver = mocker.patch(
        "activities.communications._resolve_chatops_target",
        new=mocker.AsyncMock(return_value=(provider, "soc-alerts")),
    )

    res = await teams_send_notification("t1", "", "hello")
    assert res.success is True
    resolver.assert_awaited_once_with("t1", "")
    provider.send_message.assert_awaited_once()


@pytest.mark.asyncio
async def test_teams_send_adaptive_card_error(mocker):
    provider = mocker.AsyncMock()
    provider.send_message.side_effect = RuntimeError("boom")
    mocker.patch(
        "activities.communications._resolve_chatops_target",
        new=mocker.AsyncMock(return_value=(provider, "alerts")),
    )

    with pytest.raises(ApplicationError):
        await teams_send_adaptive_card("t1", "https://example.webhook", {"type": "AdaptiveCard"})


@pytest.mark.asyncio
async def test_email_send_happy(mocker):
    mocker.patch("activities.communications.EMAIL_PROVIDER", "")
    mocker.patch(
        "activities.communications._load_secret_bundle_async",
        new=mocker.AsyncMock(return_value={"client_id": "c"}),
    )
    mocker.patch(
        "activities.communications.connector_execute_action",
        new=mocker.AsyncMock(
            return_value=type("_ActionResult", (), {
                "data": type("_Data", (), {"payload": {"message_id": "x1", "sent": True}})(),
            })()
        ),
    )
    res = await email_send("t1", "dest@example.com", "Subject", "Body")
    assert res.success is True


@pytest.mark.asyncio
async def test_email_send_defaults_to_ses_when_email_provider_unset(mocker):
    mocker.patch("activities.communications.EMAIL_PROVIDER", "")
    connector_execute_action = mocker.patch(
        "activities.communications.connector_execute_action",
        new=mocker.AsyncMock(
            return_value=type("_ActionResult", (), {
                "data": type("_Data", (), {"payload": {"message_id": "x2", "sent": True}})(),
            })()
        ),
    )
    mocker.patch(
        "activities.communications._load_secret_bundle_async",
        new=mocker.AsyncMock(return_value={"client_id": "c"}),
    )

    result = await email_send("t1", "dest@example.com", "Subject", "Body")

    assert result.success is True
    assert connector_execute_action.await_args.args[1] == "ses"


@pytest.mark.asyncio
async def test_email_send_uses_env_provider_override(mocker):
    mocker.patch("activities.communications.EMAIL_PROVIDER", "microsoft_defender")
    connector_execute_action = mocker.patch(
        "activities.communications.connector_execute_action",
        new=mocker.AsyncMock(
            return_value=type("_ActionResult", (), {
                "data": type("_Data", (), {"payload": {"message_id": "x3", "sent": True}})(),
            })()
        ),
    )
    load_bundle = mocker.patch(
        "activities.communications._load_secret_bundle_async",
        new=mocker.AsyncMock(return_value={}),
    )

    result = await email_send("t1", "dest@example.com", "Subject", "Body")

    assert result.success is True
    assert connector_execute_action.await_args.args[1] == "microsoft_defender"
    assert load_bundle.await_args.args[1] == "graph"
