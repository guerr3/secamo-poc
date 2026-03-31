"""Activity exports with lazy loading to avoid import-time side effects."""

from __future__ import annotations

from importlib import import_module

_SYMBOL_TO_MODULE = {
    "calculate_risk_score": "activities.risk",
    "collect_evidence_bundle": "activities.evidence",
    "create_audit_log": "activities.audit",
    "email_send": "activities.communications",
    "identity_assign_license": "activities.identity",
    "identity_create_user": "activities.identity",
    "identity_delete_user": "activities.identity",
    "identity_get_user": "activities.identity",
    "identity_reset_password": "activities.identity",
    "identity_revoke_sessions": "activities.identity",
    "identity_update_user": "activities.identity",
    "graph_enrich_alert": "activities.connector_dispatch",
    "graph_get_alerts": "activities.connector_dispatch",
    "device_get_context": "activities.connector_dispatch",
    "graph_isolate_device": "activities.connector_dispatch",
    "graph_list_noncompliant_devices": "activities.connector_dispatch",
    "graph_run_antivirus_scan": "activities.connector_dispatch",
    "graph_unisolate_device": "activities.connector_dispatch",
    "graph_confirm_user_compromised": "activities.connector_dispatch",
    "graph_dismiss_risky_user": "activities.connector_dispatch",
    "identity_get_risk_context": "activities.connector_dispatch",
    "graph_get_signin_history": "activities.connector_dispatch",
    "graph_list_risky_users": "activities.connector_dispatch",
    "subscription_create": "activities.connector_dispatch",
    "subscription_delete": "activities.connector_dispatch",
    "subscription_list": "activities.connector_dispatch",
    "subscription_metadata_load": "activities.connector_dispatch",
    "subscription_metadata_lookup": "activities.connector_dispatch",
    "subscription_metadata_store": "activities.connector_dispatch",
    "subscription_renew": "activities.connector_dispatch",
    "request_hitl_approval": "activities.hitl",
    "teams_send_adaptive_card": "activities.communications",
    "teams_send_notification": "activities.communications",
    "threat_intel_lookup": "activities.threat_intel",
}

__all__ = sorted(_SYMBOL_TO_MODULE.keys())


def __getattr__(name: str):
    module_name = _SYMBOL_TO_MODULE.get(name)
    if module_name is None:
        raise AttributeError(name)
    module = import_module(module_name)
    return getattr(module, name)
