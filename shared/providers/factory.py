"""Tenant-aware provider factory for AI triage and ChatOps integrations.

The factory resolves concrete provider implementations dynamically from tenant
configuration and returns protocol-compatible instances. Provider instances are
cached to reduce repeated object construction and HTTP client churn.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import boto3

from shared.models import (
    AITriageConfig,
    AITriageProvider,
    ChatOpsConfig,
    ChatOpsProvider,
    TenantConfig,
)
from shared.providers.ai import AzureOpenAITriageProvider
from shared.providers.chatops import MSTeamsChatOpsProvider, SlackChatOpsProvider


_REGION = "eu-west-1"
_CONFIG_CACHE: dict[str, TenantConfig] = {}
_AI_PROVIDER_CACHE: dict[str, AITriageProvider] = {}
_CHATOPS_PROVIDER_CACHE: dict[str, ChatOpsProvider] = {}
_CACHE_LOCK = asyncio.Lock()
_SSM_CLIENT = None


def _get_ssm_client():
    """Return a lazily created SSM client to avoid import-time side effects."""
    global _SSM_CLIENT
    if _SSM_CLIENT is None:
        _SSM_CLIENT = boto3.client("ssm", region_name=_REGION)
    return _SSM_CLIENT


def _config_path(tenant_id: str) -> str:
    """Build tenant configuration SSM base path."""
    return f"/secamo/tenants/{tenant_id}/config/"


def _safe_json_object(value: str | None) -> dict[str, Any]:
    """Parse a JSON object string and return an empty object on failure."""
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


async def _load_tenant_config_from_ssm(tenant_id: str) -> TenantConfig:
    """Load tenant configuration from SSM and map provider-specific config keys."""
    path = _config_path(tenant_id)

    def _fetch_parameters() -> dict[str, str]:
        response = _get_ssm_client().get_parameters_by_path(Path=path, WithDecryption=False)
        return {item["Name"].split("/")[-1]: item["Value"] for item in response.get("Parameters", [])}

    parameters = await asyncio.to_thread(_fetch_parameters)

    ai_json = _safe_json_object(parameters.get("ai_triage_config"))
    chatops_json = _safe_json_object(parameters.get("chatops_config"))

    ai_config = AITriageConfig.model_validate(
        {
            "provider_type": parameters.get("ai_triage_provider_type")
            or parameters.get("ai_triage_provider")
            or ai_json.get("provider_type")
            or "azure_openai",
            "credentials_path": parameters.get("ai_triage_credentials_path")
            or ai_json.get("credentials_path")
            or "/secamo/tenants/{tenant_id}/ai_triage",
            "default_channel": parameters.get("ai_triage_default_channel") or ai_json.get("default_channel"),
            "model_name": parameters.get("ai_triage_model_name") or ai_json.get("model_name"),
            "temperature": float(parameters.get("ai_triage_temperature", ai_json.get("temperature", 0.0))),
            "max_tokens": int(parameters.get("ai_triage_max_tokens", ai_json.get("max_tokens", 512))),
            "enabled": str(parameters.get("ai_triage_enabled", ai_json.get("enabled", "true"))).lower()
            in {"1", "true", "yes", "on"},
        }
    )

    default_channels_raw = parameters.get("chatops_default_channels")
    if default_channels_raw:
        default_channels = [chunk.strip() for chunk in default_channels_raw.split(",") if chunk.strip()]
    else:
        default_channels = chatops_json.get("default_channels", [])

    chatops_config = ChatOpsConfig.model_validate(
        {
            "provider_type": parameters.get("chatops_provider_type")
            or parameters.get("chatops_provider")
            or chatops_json.get("provider_type")
            or "ms_teams",
            "credentials_path": parameters.get("chatops_credentials_path")
            or chatops_json.get("credentials_path")
            or "/secamo/tenants/{tenant_id}/chatops",
            "default_channel": parameters.get("chatops_default_channel")
            or chatops_json.get("default_channel"),
            "default_channels": default_channels,
            "enabled": str(parameters.get("chatops_enabled", chatops_json.get("enabled", "true"))).lower()
            in {"1", "true", "yes", "on"},
        }
    )

    return TenantConfig(
        tenant_id=tenant_id,
        display_name=parameters.get("display_name", "Unknown Tenant"),
        ai_triage_config=ai_config,
        chatops_config=chatops_config,
    )


async def _get_tenant_config_cached(tenant_id: str) -> TenantConfig:
    """Retrieve tenant configuration from cache or SSM."""
    cached = _CONFIG_CACHE.get(tenant_id)
    if cached is not None:
        return cached

    async with _CACHE_LOCK:
        cached = _CONFIG_CACHE.get(tenant_id)
        if cached is not None:
            return cached
        loaded = await _load_tenant_config_from_ssm(tenant_id)
        _CONFIG_CACHE[tenant_id] = loaded
        return loaded


async def get_tenant_runtime_config(tenant_id: str) -> TenantConfig:
    """Return tenant runtime configuration from cache or SSM.

    This helper is intended for non-activity callers (for example ingress
    handlers) that require the same tenant config resolution behavior used by
    provider factory methods.
    """
    return await _get_tenant_config_cached(tenant_id)


def _resolve_secret(secrets: dict[str, Any], *names: str) -> str | None:
    """Return the first non-empty secret value matching any candidate key name."""
    for name in names:
        value = secrets.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


async def get_ai_provider(tenant_id: str, secrets: dict[str, Any]) -> AITriageProvider:
    """Resolve and cache the AI triage provider for a tenant.

    Args:
        tenant_id: Tenant identifier used for config lookup and cache keying.
        secrets: Tenant-scoped secret dictionary (already retrieved from SSM).

    Returns:
        A protocol-compatible AI triage provider instance.
    """
    config = await _get_tenant_config_cached(tenant_id)
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


async def get_chatops_provider(tenant_id: str, secrets: dict[str, Any]) -> ChatOpsProvider:
    """Resolve and cache the ChatOps provider for a tenant.

    Args:
        tenant_id: Tenant identifier used for config lookup and cache keying.
        secrets: Tenant-scoped secret dictionary (already retrieved from SSM).

    Returns:
        A protocol-compatible ChatOps provider instance.
    """
    config = await _get_tenant_config_cached(tenant_id)
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


def clear_provider_caches() -> None:
    """Clear factory caches; intended for unit tests."""
    _CONFIG_CACHE.clear()
    _AI_PROVIDER_CACHE.clear()
    _CHATOPS_PROVIDER_CACHE.clear()
