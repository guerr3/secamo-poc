from __future__ import annotations

from shared.routing import resolve_provider_event_route


def test_defender_alert_routes_to_case_intake() -> None:
    route = resolve_provider_event_route("microsoft_defender", "defender.alert")
    assert route == ("SocAlertTriageWorkflow", "edr")


def test_defender_impossible_travel_routes_to_case_intake() -> None:
    route = resolve_provider_event_route("microsoft_defender", "defender.impossible_travel")
    assert route == ("SocAlertTriageWorkflow", "edr")


def test_graph_security_signal_routes_to_case_intake() -> None:
    route = resolve_provider_event_route("microsoft_graph", "defender.security_signal")
    assert route == ("SocAlertTriageWorkflow", "edr")


def test_defender_alias_routes_to_case_intake() -> None:
    route = resolve_provider_event_route("defender", "alert")
    assert route == ("SocAlertTriageWorkflow", "edr")
