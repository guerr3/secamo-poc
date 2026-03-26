# Workers - Temporal runtime bootstrap and queue registration module

> This module starts Temporal workers and binds workflows and activities to task queues.

## Responsibilities

- Connect to Temporal with repository runtime settings.
- Register activities by queue and workflows by queue.
- Start queue workers concurrently for IAM, SOC, audit, and poller domains.
- Provide startup failure behavior for missing imports or runtime wiring errors.

## File Reference

| File            | Responsibility                                                           |
| --------------- | ------------------------------------------------------------------------ |
| `__init__.py`   | Package marker.                                                          |
| `README.md`     | Module documentation.                                                    |
| `run_worker.py` | Worker bootstrap, lazy imports, queue registration, and runtime startup. |
| `__pycache__/`  | Generated Python bytecode cache directory.                               |

## Key Concepts

- Queue partitioning: queue separation isolates identity, SOC, audit, and poller workloads.
- Lazy import registration: runtime validates module availability at startup to fail fast on bad wiring.
- Central runtime entrypoint: worker startup logic is consolidated in one module to reduce drift.

## Usage

Start all registered workers:

```bash
python -m workers.run_worker
```

## Testing

```bash
python -m pytest -q
```

## Extension Points

1. Add workflow imports and queue registration in `load_workflows()`.
2. Add activity imports and queue registration in `load_activities_by_queue()`.
3. Keep queue naming aligned with `shared/config.py` constants.
4. Add tests that cover startup import behavior and queue routing assumptions.
5. Update this file reference when worker module contents change.
