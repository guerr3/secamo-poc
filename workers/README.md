# Workers

> This folder contains the Temporal worker bootstrap that registers workflows/activities by task queue and runs queue workers concurrently.

## What This Does

### Files

| File            | Purpose                                                                                                                      | Used By                                                                    |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `__init__.py`   | Package marker.                                                                                                              | Python module loading.                                                     |
| `run_worker.py` | Connects to Temporal, loads workflows/activities, and starts workers for `iam-graph`, `soc-defender`, `audit`, and `poller`. | Runtime entrypoint (`python -m workers.run_worker`), Docker image command. |

This module is the executable bridge between workflow definitions in `workflows/` and activity implementations in `activities/`. Queue names and Temporal connection settings are loaded from `shared/config.py`. Infrastructure in `terraform/` supplies runtime dependencies.

## How To Run

Start workers with:

```bash
python -m workers.run_worker
```

## How To Verify

Verify startup and queue registration behavior:

```bash
python -m pytest -q
```

## Troubleshooting

- Add new workflows/activities in queue-specific sections of `load_workflows()` and `load_activities_by_queue()`.
- Keep imports lazy and explicit, matching existing error handling, so startup fails fast on missing modules.
- Queue split is part of operational isolation; avoid collapsing unrelated domains onto one queue.
