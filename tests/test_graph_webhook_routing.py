from shared.routing import resolve_webhook_route


def test_resolve_webhook_route_alerts_v2_resource() -> None:
    route = resolve_webhook_route("microsoft_graph", "/security/alerts_v2/abc-123")
    assert route == ("DefenderAlertEnrichmentWorkflow", "soc-defender")


def test_resolve_webhook_route_signins_resource() -> None:
    route = resolve_webhook_route("microsoft_graph", "auditLogs/signIns")
    assert route == ("ImpossibleTravelWorkflow", "soc-defender")


def test_resolve_webhook_route_unknown_resource() -> None:
    route = resolve_webhook_route("microsoft_graph", "users")
    assert route is None
