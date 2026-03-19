"""Activity exports with lazy loading to avoid import-time side effects."""

from __future__ import annotations

from importlib import import_module

_SYMBOL_TO_MODULE = {
    "calculate_risk_score": "activities.risk",
    "collect_evidence_bundle": "activities.evidence",
    "create_audit_log": "activities.audit",
    "email_send": "activities.notify_email",
    "graph_enrich_alert": "activities.graph_alerts",
    "graph_get_alerts": "activities.graph_alerts",
    "graph_get_device_details": "activities.graph_devices",
    "graph_isolate_device": "activities.graph_devices",
    "graph_list_noncompliant_devices": "activities.graph_devices",
    "graph_run_antivirus_scan": "activities.graph_devices",
    "graph_unisolate_device": "activities.graph_devices",
    "graph_confirm_user_compromised": "activities.graph_signin",
    "graph_dismiss_risky_user": "activities.graph_signin",
    "graph_get_risky_user": "activities.graph_signin",
    "graph_get_signin_history": "activities.graph_signin",
    "graph_list_risky_users": "activities.graph_signin",
    "create_graph_subscription": "activities.graph_subscriptions",
    "delete_graph_subscription": "activities.graph_subscriptions",
    "list_graph_subscriptions": "activities.graph_subscriptions",
    "load_subscription_metadata": "activities.graph_subscriptions",
    "lookup_subscription_metadata": "activities.graph_subscriptions",
    "renew_graph_subscription": "activities.graph_subscriptions",
    "store_subscription_metadata": "activities.graph_subscriptions",
    "request_hitl_approval": "activities.hitl",
    "teams_send_adaptive_card": "activities.notify_teams",
    "teams_send_notification": "activities.notify_teams",
    "threat_intel_lookup": "activities.threat_intel",
}

__all__ = sorted(_SYMBOL_TO_MODULE.keys())


def __getattr__(name: str):
    module_name = _SYMBOL_TO_MODULE.get(name)
    if module_name is None:
        raise AttributeError(name)
    module = import_module(module_name)
    return getattr(module, name)
