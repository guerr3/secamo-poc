"""
ingress_sdk.temporal — Singleton Temporal gRPC Client

Initializes the client once in the global scope and reuses the TCP
connection across warm Lambda invocations (cold start optimization).
"""

import logging
import os
import uuid

from temporalio.client import Client

logger = logging.getLogger("ingress_sdk.temporal")

# ── Configuration ────────────────────────────────────────────
TEMPORAL_HOST = os.environ.get("TEMPORAL_HOST", "localhost:7233")
TEMPORAL_NAMESPACE = os.environ.get("TEMPORAL_NAMESPACE", "default")

# ── Singleton Client ─────────────────────────────────────────
_client: Client | None = None


async def get_client() -> Client:
    """Lazy-initialize and cache the Temporal gRPC client."""
    global _client
    if _client is None:
        logger.info("Connecting to Temporal → %s (ns: %s)", TEMPORAL_HOST, TEMPORAL_NAMESPACE)
        _client = await Client.connect(
            TEMPORAL_HOST,
            namespace=TEMPORAL_NAMESPACE,
        )
    return _client


async def start_workflow(
    workflow: str,
    input: dict,
    *,
    tenant_id: str,
    task_queue: str,
    workflow_id: str | None = None,
) -> dict:
    """
    Start a Temporal workflow and return a summary dict.

    Args:
        workflow:    Workflow class name (e.g. "DefenderAlertEnrichmentWorkflow")
        input:       Workflow input payload (dict, will be serialized by the SDK)
        tenant_id:   Tenant identifier (used in workflow ID generation)
        task_queue:  Target task queue
        workflow_id: Optional explicit workflow ID (auto-generated if omitted)

    Returns:
        {"workflow_id": str, "run_id": str}
    """
    client = await get_client()

    if workflow_id is None:
        workflow_id = f"wf-{workflow.lower()[:20]}-{tenant_id}-{uuid.uuid4().hex[:8]}"

    handle = await client.start_workflow(
        workflow,
        input,
        id=workflow_id,
        task_queue=task_queue,
    )

    logger.info("Started workflow %s (queue=%s, tenant=%s)", handle.id, task_queue, tenant_id)

    return {
        "workflow_id": handle.id,
        "run_id": handle.result_run_id,
    }


async def signal_workflow(
    workflow_id: str,
    signal: str,
    payload: dict,
) -> dict:
    """
    Send a signal to a running Temporal workflow.

    Args:
        workflow_id: Target workflow ID
        signal:      Signal name (e.g. "approve")
        payload:     Signal payload dict

    Returns:
        {"workflow_id": str, "signal": str, "status": "signal_sent"}
    """
    client = await get_client()

    handle = client.get_workflow_handle(workflow_id)
    await handle.signal(signal, payload)

    logger.info("Sent signal '%s' to workflow %s", signal, workflow_id)

    return {
        "workflow_id": workflow_id,
        "signal": signal,
        "status": "signal_sent",
    }
