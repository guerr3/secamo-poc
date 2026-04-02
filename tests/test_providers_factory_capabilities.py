from __future__ import annotations

import pytest

from shared.models import TenantConfig
from shared.providers.factory import (
    clear_provider_caches,
    get_edr_provider,
    get_identity_access_provider,
    get_subscription_provider,
    get_threat_intel_provider,
    get_ticketing_provider,
)


@pytest.mark.asyncio
async def test_get_identity_access_provider_uses_connector_cache(mocker):
    clear_provider_caches()
    connector = object()
    connector_lookup = mocker.patch("shared.providers.factory.get_connector", return_value=connector)

    config = TenantConfig(tenant_id="tenant-1", iam_provider="microsoft_graph")
    secrets = {
        "client_id": "cid",
        "client_secret": "sec",
        "tenant_azure_id": "tid",
    }

    p1 = await get_identity_access_provider("tenant-1", secrets, config)
    p2 = await get_identity_access_provider("tenant-1", secrets, config)

    assert p1 is p2
    connector_lookup.assert_called_once()
    args = connector_lookup.call_args.args
    assert args[0] == "microsoft_graph"
    assert args[1] == "tenant-1"


@pytest.mark.asyncio
async def test_get_identity_access_provider_maps_entra_id_to_graph_connector(mocker):
    clear_provider_caches()
    connector = object()
    connector_lookup = mocker.patch("shared.providers.factory.get_connector", return_value=connector)

    config = TenantConfig(tenant_id="tenant-2", iam_provider="entra_id")
    secrets = {
        "client_id": "cid",
        "client_secret": "sec",
        "tenant_azure_id": "tid",
    }

    await get_identity_access_provider("tenant-2", secrets, config)

    connector_lookup.assert_called_once()
    args = connector_lookup.call_args.args
    assert args[0] == "microsoft_graph"


@pytest.mark.asyncio
async def test_get_ticketing_provider_uses_connector_cache(mocker):
    clear_provider_caches()
    connector = object()
    connector_lookup = mocker.patch("shared.providers.factory.get_connector", return_value=connector)

    config = TenantConfig(tenant_id="tenant-3", ticketing_provider="jira")
    secrets = {
        "jira_base_url": "https://jira.example.com",
        "jira_email": "user@example.com",
        "jira_api_token": "token",
        "project_key": "SOC",
    }

    p1 = await get_ticketing_provider("tenant-3", secrets, config)
    p2 = await get_ticketing_provider("tenant-3", secrets, config)

    assert p1 is p2
    connector_lookup.assert_called_once()
    args = connector_lookup.call_args.args
    assert args[0] == "jira"
    assert args[1] == "tenant-3"


@pytest.mark.asyncio
async def test_get_identity_access_provider_rejects_unimplemented_provider():
    clear_provider_caches()
    config = TenantConfig(tenant_id="tenant-4", iam_provider="okta")

    with pytest.raises(NotImplementedError):
        await get_identity_access_provider("tenant-4", {}, config)


@pytest.mark.asyncio
async def test_get_edr_provider_uses_connector_cache(mocker):
    clear_provider_caches()
    connector = object()
    connector_lookup = mocker.patch("shared.providers.factory.get_connector", return_value=connector)

    secrets = {
        "client_id": "cid",
        "client_secret": "sec",
        "tenant_azure_id": "tid",
    }

    p1 = await get_edr_provider("tenant-5", secrets, provider="microsoft_defender")
    p2 = await get_edr_provider("tenant-5", secrets, provider="microsoft_defender")

    assert p1 is p2
    connector_lookup.assert_called_once()
    args = connector_lookup.call_args.args
    assert args[0] == "microsoft_defender"
    assert args[1] == "tenant-5"


@pytest.mark.asyncio
async def test_get_threat_intel_provider_uses_cache():
    clear_provider_caches()
    secrets = {
        "client_id": "cid",
        "client_secret": "sec",
        "tenant_azure_id": "tid",
        "virustotal_api_key": "vt",
    }

    p1 = await get_threat_intel_provider("tenant-6", secrets, default_provider="virustotal")
    p2 = await get_threat_intel_provider("tenant-6", secrets, default_provider="virustotal")

    assert p1 is p2


@pytest.mark.asyncio
async def test_get_subscription_provider_maps_graph_and_uses_cache(mocker):
    clear_provider_caches()
    connector = object()
    connector_lookup = mocker.patch("shared.providers.factory.get_connector", return_value=connector)

    secrets = {
        "client_id": "cid",
        "client_secret": "sec",
        "tenant_azure_id": "tid",
    }

    p1 = await get_subscription_provider("tenant-7", secrets, provider="microsoft_graph")
    p2 = await get_subscription_provider("tenant-7", secrets, provider="microsoft_graph")

    assert p1 is p2
    connector_lookup.assert_called_once()
    args = connector_lookup.call_args.args
    assert args[0] == "microsoft_defender"
    assert args[1] == "tenant-7"
