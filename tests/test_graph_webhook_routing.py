from shared.routing import resolve_webhook_route
from shared.routing.defaults import build_default_route_registry


# ---------------------------------------------------------------------------
# Defender alert path – must remain unchanged
# ---------------------------------------------------------------------------

def test_resolve_webhook_route_alerts_v2_resource() -> None:
    route = resolve_webhook_route("microsoft_graph", "/security/alerts_v2/abc-123")
    assert route == ("SocAlertTriageWorkflow", "edr")


def test_resolve_webhook_route_unknown_resource() -> None:
    route = resolve_webhook_route("microsoft_graph", "users")
    assert route is None


# ---------------------------------------------------------------------------
# Security-signal path – sign-in and risky-user must NOT resolve via
# resolve_webhook_route (which returns a fallback route, not a predicate
# result).  The correct seam is the registry's webhook resource → event-type
# mapping, which must now yield "defender.security_signal" for both resources.
# ---------------------------------------------------------------------------

def test_webhook_resource_auditlogs_signins_maps_to_security_signal() -> None:
    """auditLogs/signIns must map to the defender.security_signal event family."""
    registry = build_default_route_registry()
    # The registry's webhook resource map stores normalised lower-case keys.
    # We query the internal dict rather than going through resolve_webhook (which
    # also follows fallback routes) so that this test is deliberately isolated to
    # the classification step alone.
    from shared.routing.registry import RouteRegistry
    resource_key = RouteRegistry._resource_key("microsoft_graph", "auditlogs/signins")
    mapped = registry._webhook_resource_event_types.get(resource_key)
    assert mapped == "defender.security_signal", (
        f"expected 'defender.security_signal', got {mapped!r}"
    )


def test_webhook_resource_riskyusers_maps_to_security_signal() -> None:
    """identityProtection/riskyUsers must map to the defender.security_signal event family."""
    registry = build_default_route_registry()
    from shared.routing.registry import RouteRegistry
    resource_key = RouteRegistry._resource_key("microsoft_graph", "identityprotection/riskyusers")
    mapped = registry._webhook_resource_event_types.get(resource_key)
    assert mapped == "defender.security_signal", (
        f"expected 'defender.security_signal', got {mapped!r}"
    )
