"""Tenant-aware provider factory for capability-based integrations.

The factory resolves concrete provider implementations dynamically from tenant
configuration and returns protocol-compatible instances. Provider instances are
cached to reduce repeated object construction and HTTP client churn.

IMPORTANT: Callers must supply a ``TenantConfig`` obtained from the canonical
``activities.tenant.get_tenant_config`` activity.  The factory does NOT load
configuration from SSM itself — this eliminates the config-divergence bug where
the factory and activities disagreed on field parsing.
"""

from __future__ import annotations

import asyncio
from typing import Any

from connectors.registry import get_connector
from shared.models import TenantConfig
from shared.providers.contracts import TenantSecrets
from shared.providers.ai import AzureOpenAITriageProvider
from shared.providers.chatops import MSTeamsChatOpsProvider, SlackChatOpsProvider
from shared.providers.edr import ConnectorEDRProvider
from shared.providers.identity_access import ConnectorIdentityAccessProvider
from shared.providers.protocols import (
    AITriageProvider,
    ChatOpsProvider,
    EDRProvider,
    IdentityAccessProvider,
    SubscriptionProvider,
    ThreatIntelProvider,
    TicketingProvider,
)
from shared.providers.subscription import ConnectorSubscriptionProvider
from shared.providers.ticketing import ConnectorTicketingProvider
from shared.providers.threat_intel import ConnectorThreatIntelProvider


_AI_PROVIDER_CACHE: dict[str, AITriageProvider] = {}
_CHATOPS_PROVIDER_CACHE: dict[str, ChatOpsProvider] = {}
_EDR_PROVIDER_CACHE: dict[str, EDRProvider] = {}
_IDENTITY_PROVIDER_CACHE: dict[str, IdentityAccessProvider] = {}
_SUBSCRIPTION_PROVIDER_CACHE: dict[str, SubscriptionProvider] = {}
_THREAT_INTEL_PROVIDER_CACHE: dict[str, ThreatIntelProvider] = {}
_TICKETING_PROVIDER_CACHE: dict[str, TicketingProvider] = {}
_CACHE_LOCK = asyncio.Lock()


def _resolve_secret(secrets: dict[str, Any], *names: str) -> str | None:
    """Return the first non-empty secret value matching any candidate key name."""
    for name in names:
        value = secrets.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _to_tenant_secrets(secrets: dict[str, Any] | TenantSecrets) -> TenantSecrets:
    """Normalize loose secret dictionaries into connector-ready tenant secrets."""
    if isinstance(secrets, TenantSecrets):
        return secrets

    return TenantSecrets(
        client_id=_resolve_secret(secrets, "client_id") or "",
        client_secret=_resolve_secret(secrets, "client_secret") or "",
        tenant_azure_id=_resolve_secret(secrets, "tenant_azure_id") or "",
        teams_webhook_url=_resolve_secret(secrets, "teams_webhook_url", "webhook_url"),
        jira_base_url=_resolve_secret(secrets, "jira_base_url", "base_url"),
        jira_email=_resolve_secret(secrets, "jira_email"),
        jira_api_token=_resolve_secret(secrets, "jira_api_token", "api_token"),
        project_key=_resolve_secret(secrets, "project_key"),
        project_type=(_resolve_secret(secrets, "project_type") or "standard").lower(),
        jsm_service_desk_id=_resolve_secret(secrets, "jsm_service_desk_id"),
        jsm_request_type_id=_resolve_secret(secrets, "jsm_request_type_id"),
        virustotal_api_key=_resolve_secret(secrets, "virustotal_api_key"),
        abuseipdb_api_key=_resolve_secret(secrets, "abuseipdb_api_key"),
    )


async def get_ai_provider(
    tenant_id: str,
    secrets: dict[str, Any],
    config: TenantConfig,
) -> AITriageProvider:
    """Resolve and cache the AI triage provider for a tenant.

    Args:
        tenant_id: Tenant identifier used for cache keying.
        secrets: Tenant-scoped secret dictionary (already retrieved from SSM).
        config: TenantConfig obtained from the canonical get_tenant_config activity.

    Returns:
        A protocol-compatible AI triage provider instance.
    """
    provider_type = config.ai_triage_config.provider_type

    cache_key = f"ai:{tenant_id}:{provider_type}:{config.ai_triage_config.model_name or 'default'}"
    cached = _AI_PROVIDER_CACHE.get(cache_key)
    if cached is not None:
        return cached

    if provider_type == "azure_openai":
        endpoint = _resolve_secret(secrets, "azure_openai_endpoint", "endpoint")
        api_key = _resolve_secret(secrets, "azure_openai_api_key", "api_key")
        deployment_id = _resolve_secret(
            secrets,
            "azure_openai_deployment",
            "deployment_id",
            "model_deployment",
        ) or config.ai_triage_config.model_name

        if not endpoint or not api_key or not deployment_id:
            raise ValueError(
                "Azure OpenAI triage configuration is incomplete; expected endpoint, api_key, and deployment_id"
            )

        provider: AITriageProvider = AzureOpenAITriageProvider(
            endpoint=endpoint,
            api_key=api_key,
            deployment_id=deployment_id,
            temperature=config.ai_triage_config.temperature,
            max_tokens=config.ai_triage_config.max_tokens,
        )
    elif provider_type in {"aws_bedrock", "local"}:
        raise NotImplementedError(f"AI provider '{provider_type}' is not implemented yet")
    else:
        raise ValueError(f"Unsupported AI provider_type '{provider_type}'")

    async with _CACHE_LOCK:
        existing = _AI_PROVIDER_CACHE.get(cache_key)
        if existing is not None:
            return existing
        _AI_PROVIDER_CACHE[cache_key] = provider
    return provider


async def get_chatops_provider(
    tenant_id: str,
    secrets: dict[str, Any],
    config: TenantConfig,
) -> ChatOpsProvider:
    """Resolve and cache the ChatOps provider for a tenant.

    Args:
        tenant_id: Tenant identifier used for cache keying.
        secrets: Tenant-scoped secret dictionary (already retrieved from SSM).
        config: TenantConfig obtained from the canonical get_tenant_config activity.

    Returns:
        A protocol-compatible ChatOps provider instance.
    """
    provider_type = config.chatops_config.provider_type

    cache_key = f"chatops:{tenant_id}:{provider_type}:{config.chatops_config.default_channel or 'default'}"
    cached = _CHATOPS_PROVIDER_CACHE.get(cache_key)
    if cached is not None:
        return cached

    if provider_type == "ms_teams":
        webhook_url = _resolve_secret(secrets, "teams_webhook_url", "webhook_url")
        signing_secret = _resolve_secret(secrets, "teams_signing_secret", "signing_secret")
        if not webhook_url:
            raise ValueError("MS Teams ChatOps configuration is incomplete; expected teams_webhook_url")

        provider: ChatOpsProvider = MSTeamsChatOpsProvider(
            webhook_url=webhook_url,
            signing_secret=signing_secret,
        )
    elif provider_type == "slack":
        webhook_url = _resolve_secret(secrets, "slack_webhook_url", "webhook_url")
        bot_token = _resolve_secret(secrets, "slack_bot_token", "bot_token")
        signing_secret = _resolve_secret(secrets, "slack_signing_secret", "signing_secret")
        provider = SlackChatOpsProvider(
            webhook_url=webhook_url,
            bot_token=bot_token,
            signing_secret=signing_secret,
        )
    else:
        raise ValueError(f"Unsupported ChatOps provider_type '{provider_type}'")

    async with _CACHE_LOCK:
        existing = _CHATOPS_PROVIDER_CACHE.get(cache_key)
        if existing is not None:
            return existing
        _CHATOPS_PROVIDER_CACHE[cache_key] = provider
    return provider


async def get_identity_access_provider(
    tenant_id: str,
    secrets: dict[str, Any],
    config: TenantConfig,
) -> IdentityAccessProvider:
    """Resolve and cache the identity access provider for a tenant."""
    provider_type = config.iam_provider
    cache_key = f"identity:{tenant_id}:{provider_type}"
    cached = _IDENTITY_PROVIDER_CACHE.get(cache_key)
    if cached is not None:
        return cached

    if provider_type in {"microsoft_graph", "entra_id"}:
        connector_provider = "microsoft_graph"
    elif provider_type in {"okta", "custom"}:
        raise NotImplementedError(f"Identity provider '{provider_type}' is not implemented yet")
    else:
        raise ValueError(f"Unsupported iam_provider '{provider_type}'")

    tenant_secrets = _to_tenant_secrets(secrets)
    connector = get_connector(connector_provider, tenant_id, tenant_secrets)
    provider: IdentityAccessProvider = ConnectorIdentityAccessProvider(
        identity_provider=provider_type,
        connector=connector,
    )

    async with _CACHE_LOCK:
        existing = _IDENTITY_PROVIDER_CACHE.get(cache_key)
        if existing is not None:
            return existing
        _IDENTITY_PROVIDER_CACHE[cache_key] = provider
    return provider


async def get_edr_provider(
    tenant_id: str,
    secrets: dict[str, Any] | TenantSecrets,
    *,
    provider: str = "microsoft_defender",
) -> EDRProvider:
    """Resolve and cache the EDR provider for a tenant."""
    provider_type = provider.strip().lower() or "microsoft_defender"
    cache_key = f"edr:{tenant_id}:{provider_type}"
    cached = _EDR_PROVIDER_CACHE.get(cache_key)
    if cached is not None:
        return cached

    tenant_secrets = _to_tenant_secrets(secrets)
    connector = get_connector(provider_type, tenant_id, tenant_secrets)
    provider_instance: EDRProvider = ConnectorEDRProvider(connector=connector)

    async with _CACHE_LOCK:
        existing = _EDR_PROVIDER_CACHE.get(cache_key)
        if existing is not None:
            return existing
        _EDR_PROVIDER_CACHE[cache_key] = provider_instance
    return provider_instance


async def get_threat_intel_provider(
    tenant_id: str,
    secrets: dict[str, Any] | TenantSecrets,
    *,
    default_provider: str = "virustotal",
) -> ThreatIntelProvider:
    """Resolve and cache the threat-intel provider for a tenant."""
    provider_type = default_provider.strip().lower() or "virustotal"
    cache_key = f"threat-intel:{tenant_id}:{provider_type}"
    cached = _THREAT_INTEL_PROVIDER_CACHE.get(cache_key)
    if cached is not None:
        return cached

    tenant_secrets = _to_tenant_secrets(secrets)
    provider_instance: ThreatIntelProvider = ConnectorThreatIntelProvider(
        tenant_id=tenant_id,
        secrets=tenant_secrets,
        default_provider=provider_type,
    )

    async with _CACHE_LOCK:
        existing = _THREAT_INTEL_PROVIDER_CACHE.get(cache_key)
        if existing is not None:
            return existing
        _THREAT_INTEL_PROVIDER_CACHE[cache_key] = provider_instance
    return provider_instance


async def get_subscription_provider(
    tenant_id: str,
    secrets: dict[str, Any] | TenantSecrets,
    *,
    provider: str = "microsoft_defender",
) -> SubscriptionProvider:
    """Resolve and cache the subscription provider for a tenant."""
    provider_type = provider.strip().lower() or "microsoft_defender"
    connector_provider = "microsoft_defender" if provider_type == "microsoft_graph" else provider_type
    cache_key = f"subscription:{tenant_id}:{connector_provider}"
    cached = _SUBSCRIPTION_PROVIDER_CACHE.get(cache_key)
    if cached is not None:
        return cached

    tenant_secrets = _to_tenant_secrets(secrets)
    connector = get_connector(connector_provider, tenant_id, tenant_secrets)
    provider_instance: SubscriptionProvider = ConnectorSubscriptionProvider(
        tenant_id=tenant_id,
        connector=connector,
    )

    async with _CACHE_LOCK:
        existing = _SUBSCRIPTION_PROVIDER_CACHE.get(cache_key)
        if existing is not None:
            return existing
        _SUBSCRIPTION_PROVIDER_CACHE[cache_key] = provider_instance
    return provider_instance


async def get_ticketing_provider(
    tenant_id: str,
    secrets: dict[str, Any],
    config: TenantConfig,
) -> TicketingProvider:
    """Resolve and cache the ticketing provider for a tenant."""
    provider_type = config.ticketing_provider
    cache_key = f"ticketing:{tenant_id}:{provider_type}:{config.display_name}"
    cached = _TICKETING_PROVIDER_CACHE.get(cache_key)
    if cached is not None:
        return cached

    if provider_type not in {"jira", "halo_itsm", "servicenow"}:
        raise ValueError(f"Unsupported ticketing_provider '{provider_type}'")

    tenant_secrets = _to_tenant_secrets(secrets)
    connector = get_connector(provider_type, tenant_id, tenant_secrets)
    provider: TicketingProvider = ConnectorTicketingProvider(
        ticketing_provider=provider_type,
        connector=connector,
        ticket_base_url=tenant_secrets.jira_base_url,
        default_project_key=tenant_secrets.project_key or "SOC",
    )

    async with _CACHE_LOCK:
        existing = _TICKETING_PROVIDER_CACHE.get(cache_key)
        if existing is not None:
            return existing
        _TICKETING_PROVIDER_CACHE[cache_key] = provider
    return provider


def clear_provider_caches() -> None:
    """Clear factory caches; intended for unit tests."""
    _AI_PROVIDER_CACHE.clear()
    _CHATOPS_PROVIDER_CACHE.clear()
    _EDR_PROVIDER_CACHE.clear()
    _IDENTITY_PROVIDER_CACHE.clear()
    _SUBSCRIPTION_PROVIDER_CACHE.clear()
    _THREAT_INTEL_PROVIDER_CACHE.clear()
    _TICKETING_PROVIDER_CACHE.clear()
