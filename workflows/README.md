# Workflows - deterministic orchestration layer for security automation

> This module defines parent orchestration workflows and composes child workflows for reusable sub-flows.

## Responsibilities

- Orchestrate event-driven business flow execution in a deterministic manner.
- Coordinate activity calls, child workflow execution, signals, and retries.
- Separate parent workflow intent routing from child workflow sub-process reuse.
- Keep direct external side effects out of workflow code.

## File Reference

| File                            | Responsibility                                                                    |
| ------------------------------- | --------------------------------------------------------------------------------- |
| `__init__.py`                   | Workflow package marker.                                                          |
| `child/`                        | Reusable child workflows for enrichment, approvals, response, and deprovisioning. |
| `defender_alert_enrichment.py`  | Parent SOC enrichment orchestration workflow.                                     |
| `iam_onboarding.py`             | IAM lifecycle orchestration workflow.                                             |
| `impossible_travel.py`          | Impossible-travel triage and incident response orchestration workflow.            |
| `polling_manager.py`            | Polling-based provider event collection and downstream dispatch workflow.         |
| `README.md`                     | Module documentation.                                                             |
| `__pycache__/`                  | Generated Python bytecode cache directory.                                        |

## Key Concepts

- Determinism: workflows orchestrate only; all I/O is delegated to activities.
- Composition: parent workflows call child workflows for reusable steps and clearer failure boundaries.
- Queue-aware orchestration: workflow registration aligns with queue partitioning in worker bootstrap.

## Usage

Workflows execute through Temporal workers and are started by ingress dispatch or scheduled/manual triggers.

```bash
python -m workers.run_worker
```

## Testing

```bash
python -m pytest -q
```

## Extension Points

1. Add a new workflow file under `workflows/` or `workflows/child/`.
2. Register the workflow in `workers/run_worker.py` for the intended queue.
3. Add or update routes in `shared/routing/defaults.py` when ingress-triggered.
4. Add tests covering expected orchestration branches and failure paths.
5. Update this file reference and related architecture docs.
