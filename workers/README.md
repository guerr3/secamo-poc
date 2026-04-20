# Workers

Worker bootstrap and runtime queue registration for the Temporal execution layer.

## What This Module Owns

- Temporal client connection setup.
- Workflow/activity loading by queue domain.
- Startup validation for route-to-worker parity.
- Concurrent startup of queue-specific worker processes.

## Queue Domains

Workers are started for the following queues:

- `user-lifecycle`
- `edr`
- `ticketing`
- `interactions`
- `audit`
- `polling`

## Runtime Notes (Current Behavior)

- Imports are loaded lazily and startup fails fast on missing workflow/activity modules.
- `_validate_route_worker_parity` validates that every registered route points to a registered workflow and queue.
- Unrouted but registered workflows are logged as warnings to surface drift early.

## Run and Verify

Start all workers:

```bash
python -m workers.run_worker
```

Run worker wiring tests:

```bash
python -m pytest -q tests/test_worker_entrypoint.py tests/test_worker_signal_registration.py tests/test_worker_registration_customer_onboarding.py tests/test_workflow_stage_registration.py
```

## Change Checklist

1. Add workflow imports and queue mapping in `load_workflows()`.
2. Add activity imports and queue mapping in `load_activities_by_queue()`.
3. Keep queue constants aligned with `shared/config.py`.
4. Keep route mappings aligned with `shared/routing/defaults.py`.
5. Update worker tests whenever registration behavior changes.
