# Workers

> This folder contains the Temporal worker bootstrap that registers workflows/activities by task queue and runs queue workers concurrently.

## Files

| File | Purpose | Used By |
|------|---------|---------|
| `__init__.py` | Package marker. | Python module loading. |
| `run_worker.py` | Connects to Temporal, loads workflows/activities, and starts workers for `iam-graph`, `soc-defender`, `audit`, and `poller`. | Runtime entrypoint (`python -m workers.run_worker`), Docker image command. |

## How It Fits

This is the executable bridge between workflow definitions in [../workflows/README.md](../workflows/README.md) and activity implementations in [../activities/README.md](../activities/README.md). Queue names and Temporal connection parameters come from [../shared/README.md](../shared/README.md). In deployed environments, infrastructure in [../terraform/README.md](../terraform/README.md) supplies the runtime dependencies and parameters.

## Notes / Extension Points

- Add new workflows/activities in queue-specific sections of `load_workflows()` and `load_activities_by_queue()`.
- Keep imports lazy and explicit, matching existing error handling, so startup fails fast on missing modules.
- Queue split is part of operational isolation; avoid collapsing unrelated domains onto one queue.
