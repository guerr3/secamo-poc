"""Activity exports with lazy loading to avoid import-time side effects."""

from __future__ import annotations

from importlib import import_module

_SYMBOL_TO_MODULE = {
    "calculate_risk_score": "activities.risk",
    "collect_evidence_bundle": "activities.evidence",
    "create_audit_log": "activities.audit",
    "provision_customer_secrets": "activities.onboarding",
    "register_customer_tenant": "activities.onboarding",
    "email_send": "activities.communications",
    "identity_assign_license": "activities.identity",
    "identity_create_user": "activities.identity",
    "identity_delete_user": "activities.identity",
    "identity_get_user": "activities.identity",
    "identity_reset_password": "activities.identity",
    "identity_revoke_sessions": "activities.identity",
    "identity_update_user": "activities.identity",
    "edr_enrich_alert": "activities.edr",
    "edr_fetch_events": "activities.edr",
    "edr_get_device_context": "activities.edr",
    "edr_isolate_device": "activities.edr",
    "edr_unisolate_device": "activities.edr",
    "edr_run_antivirus_scan": "activities.edr",
    "edr_list_noncompliant_devices": "activities.edr",
    "edr_get_user_alerts": "activities.edr",
    "edr_confirm_user_compromised": "activities.edr",
    "edr_dismiss_risky_user": "activities.edr",
    "edr_get_signin_history": "activities.edr",
    "edr_list_risky_users": "activities.edr",
    "edr_get_identity_risk": "activities.edr",
    "subscription_create": "activities.subscription",
    "subscription_delete": "activities.subscription",
    "subscription_list": "activities.subscription",
    "subscription_metadata_load": "activities.subscription",
    "subscription_metadata_lookup": "activities.subscription",
    "subscription_metadata_store": "activities.subscription",
    "subscription_renew": "activities.subscription",
    "connector_fetch_events": "activities.provider_capabilities",
    "connector_execute_action": "activities.provider_capabilities",
    "connector_health_check": "activities.provider_capabilities",
    "connector_threat_intel_fanout": "activities.provider_capabilities",
    "request_hitl_approval": "activities.hitl",
    "teams_send_adaptive_card": "activities.communications",
    "teams_send_notification": "activities.communications",
    "threat_intel_fanout": "activities.threat_intel",
    "threat_intel_lookup": "activities.threat_intel",
}

__all__ = sorted(_SYMBOL_TO_MODULE.keys())


def __getattr__(name: str):
    module_name = _SYMBOL_TO_MODULE.get(name)
    if module_name is None:
        raise AttributeError(name)
    module = import_module(module_name)
    return getattr(module, name)
