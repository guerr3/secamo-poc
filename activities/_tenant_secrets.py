"""Thin adapter for synchronous tenant secret loading in non-activity contexts.

Delegates to ``activities.tenant.get_tenant_secrets`` (the canonical path) by
running it via ``asyncio``.  This ensures JSM provisioning and graph-secret
validation are consistently applied regardless of the caller.

IMPORTANT: Prefer calling ``get_tenant_secrets`` directly as a Temporal activity
when inside a workflow.  Use this helper only in synchronous code paths (e.g.
connector_dispatch) that already run inside an activity context.
"""

from __future__ import annotations

import asyncio

from shared.providers.contracts import TenantSecrets


def load_tenant_secrets(tenant_id: str, secret_type: str) -> TenantSecrets:
    """Load tenant secrets through the canonical activity function.

    Runs the async ``get_tenant_secrets`` activity function synchronously.
    The activity context must already be set by the calling Temporal activity.
    """
    from activities.tenant import get_tenant_secrets

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop.is_running():
        # We are inside a running event loop (standard Temporal activity case).
        # Run synchronously via a new thread to avoid blocking the loop.
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, get_tenant_secrets(tenant_id, secret_type)).result()
    else:
        return asyncio.run(get_tenant_secrets(tenant_id, secret_type))
