# Child Workflows - reusable sub-processes for parent orchestration flows

> This module contains child workflows that encapsulate repeatable orchestration stages used by parent workflows.

## Responsibilities

- Provide reusable enrichment, approval, response, ticketing, and deprovisioning stages.
- Keep parent workflows focused on high-level branching and sequencing logic.
- Isolate signal/timeouts and scoped sub-process behavior in dedicated workflow classes.
- Preserve deterministic execution semantics at child workflow boundaries.

## File Reference

| File                         | Responsibility                                               |
| ---------------------------- | ------------------------------------------------------------ |
| `__init__.py`                | Child workflow export surface.                               |
| `alert_enrichment.py`        | Child workflow for alert enrichment and risk context.        |
| `hitl_approval.py`           | Child workflow for human-in-the-loop approval signal flow.   |
| `incident_response.py`       | Child workflow for decision-based incident response actions. |
| `README.md`                  | Module documentation.                                        |
| `threat_intel_enrichment.py` | Child workflow for threat intel fanout stage.                |
| `ticket_creation.py`         | Child workflow for ticket creation stage.                    |
| `user_deprovisioning.py`     | Child workflow for user deprovisioning stage.                |
| `__pycache__/`               | Generated Python bytecode cache directory.                   |

## Key Concepts

- Reusable orchestration units: child workflows are composed by multiple parent workflows to avoid duplication.
- Signal-aware flow control: HiTL child workflow handles signal wait and timeout logic in one bounded module.
- Explicit stage contracts: each child workflow has a focused role and narrow input/output expectations.

## Usage

Parent workflows invoke child workflows as sub-steps in larger orchestration paths.

```python
await workflow.execute_child_workflow(
    ChildWorkflow.run,
    child_input,
)
```

## Testing

```bash
python -m pytest -q
```

## Extension Points

1. Add a new child workflow module under `workflows/child/`.
2. Export/register the class where required for worker loading.
3. Integrate it from parent workflows where composition is needed.
4. Add tests for child-specific branching, signal, and timeout behavior.
5. Update this file reference and parent workflow docs.
