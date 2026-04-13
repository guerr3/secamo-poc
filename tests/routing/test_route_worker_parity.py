from __future__ import annotations

import pytest

from shared.routing.contracts import WorkflowRoute
from shared.routing.registry import RouteRegistry
from workers import run_worker


def test_route_worker_parity_happy_path() -> None:
    workflows_map = run_worker.load_workflows()
    run_worker._validate_route_worker_parity(workflows_map)


def test_route_worker_parity_fails_for_unregistered_workflow(mocker) -> None:
    registry = RouteRegistry()
    registry.register(
        "microsoft_graph",
        "defender.alert",
        (WorkflowRoute(workflow_name="NotRegisteredWorkflow", task_queue="edr"),),
    )
    mocker.patch("workers.run_worker.build_default_route_registry", return_value=registry)

    workflows_map = run_worker.load_workflows()
    with pytest.raises(RuntimeError, match="NotRegisteredWorkflow"):
        run_worker._validate_route_worker_parity(workflows_map)
