from __future__ import annotations

from botocore.exceptions import ClientError
import pytest

from connectors.errors import (
    ConnectorPermanentError,
    ConnectorTransientError,
    ConnectorUnsupportedActionError,
)
from connectors.ses import SesConnector
from shared.providers.contracts import TenantSecrets


@pytest.fixture
def ses_secrets() -> TenantSecrets:
    return TenantSecrets(
        tenant_azure_id="tenant-1",
        client_id="client-id",
        client_secret="client-secret",
    )


@pytest.mark.asyncio
async def test_ses_send_email_success_text_body(mocker, ses_secrets):
    ses_client = mocker.Mock()
    ses_client.send_email.return_value = {"MessageId": "ses-msg-1"}
    mocker.patch("connectors.ses.boto3.client", return_value=ses_client)

    connector = SesConnector(tenant_id="tenant-1", secrets=ses_secrets)
    result = await connector.execute_action(
        "send_email",
        {
            "sender": "sender@example.com",
            "to": "dest@example.com",
            "subject": "Test subject",
            "body": "Test body",
            "content_type": "Text",
        },
    )

    assert result["success"] is True
    assert result["sent"] is True
    assert result["message_id"] == "ses-msg-1"

    sent_kwargs = ses_client.send_email.call_args.kwargs
    assert sent_kwargs["Source"] == "sender@example.com"
    assert sent_kwargs["Destination"]["ToAddresses"] == ["dest@example.com"]
    assert sent_kwargs["Message"]["Body"]["Text"]["Data"] == "Test body"


@pytest.mark.asyncio
async def test_ses_send_email_uses_html_body_when_requested(mocker, ses_secrets):
    ses_client = mocker.Mock()
    ses_client.send_email.return_value = {"MessageId": "ses-msg-2"}
    mocker.patch("connectors.ses.boto3.client", return_value=ses_client)

    connector = SesConnector(tenant_id="tenant-1", secrets=ses_secrets)
    await connector.execute_action(
        "send_email",
        {
            "sender": "sender@example.com",
            "to": ["a@example.com", "b@example.com"],
            "subject": "HTML subject",
            "body": "<b>Hello</b>",
            "content_type": "HTML",
        },
    )

    sent_kwargs = ses_client.send_email.call_args.kwargs
    assert sent_kwargs["Destination"]["ToAddresses"] == ["a@example.com", "b@example.com"]
    assert sent_kwargs["Message"]["Body"]["Html"]["Data"] == "<b>Hello</b>"


@pytest.mark.asyncio
async def test_ses_send_email_translates_throttling_to_transient_error(mocker, ses_secrets):
    ses_client = mocker.Mock()
    ses_client.send_email.side_effect = ClientError(
        error_response={"Error": {"Code": "Throttling", "Message": "rate exceeded"}},
        operation_name="SendEmail",
    )
    mocker.patch("connectors.ses.boto3.client", return_value=ses_client)

    connector = SesConnector(tenant_id="tenant-1", secrets=ses_secrets)
    with pytest.raises(ConnectorTransientError):
        await connector.execute_action(
            "send_email",
            {
                "sender": "sender@example.com",
                "to": "dest@example.com",
                "subject": "Test",
                "body": "Body",
            },
        )


@pytest.mark.asyncio
async def test_ses_send_email_translates_message_rejected_to_permanent_error(mocker, ses_secrets):
    ses_client = mocker.Mock()
    ses_client.send_email.side_effect = ClientError(
        error_response={"Error": {"Code": "MessageRejected", "Message": "address not verified"}},
        operation_name="SendEmail",
    )
    mocker.patch("connectors.ses.boto3.client", return_value=ses_client)

    connector = SesConnector(tenant_id="tenant-1", secrets=ses_secrets)
    with pytest.raises(ConnectorPermanentError):
        await connector.execute_action(
            "send_email",
            {
                "sender": "sender@example.com",
                "to": "dest@example.com",
                "subject": "Test",
                "body": "Body",
            },
        )


@pytest.mark.asyncio
async def test_ses_send_email_rejects_unsupported_action(mocker, ses_secrets):
    mocker.patch("connectors.ses.boto3.client", return_value=mocker.Mock())

    connector = SesConnector(tenant_id="tenant-1", secrets=ses_secrets)
    with pytest.raises(ConnectorUnsupportedActionError):
        await connector.execute_action("create_ticket", {})
