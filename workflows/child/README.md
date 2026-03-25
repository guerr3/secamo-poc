# Child Workflows

> This folder contains reusable Temporal child workflows that parent workflows compose for enrichment, approvals, response, ticketing, and deprovisioning.

## What This Does

### Files

| File                         | Purpose                                                                                             | Used By                                                                     |
| ---------------------------- | --------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| `__init__.py`                | Re-exports child workflow classes.                                                                  | Parent workflow imports and worker registration.                            |
| `alert_enrichment.py`        | Enriches alert context with connector, device/user details, and risk scoring.                       | `workflows/defender_alert_enrichment.py`.                                   |
| `hitl_approval.py`           | Sends HITL request, waits for approval signal, and applies timeout policy.                          | `workflows/impossible_travel.py`.                                           |
| `incident_response.py`       | Executes final analyst decision actions (dismiss/isolate/disable) and optional evidence collection. | `workflows/impossible_travel.py`.                                           |
| `threat_intel_enrichment.py` | Runs threat intel fanout activity and returns provider results.                                     | `workflows/defender_alert_enrichment.py`, `workflows/impossible_travel.py`. |
| `ticket_creation.py`         | Creates SOC ticket through connector action and normalizes ticket result.                           | `workflows/defender_alert_enrichment.py`, `workflows/impossible_travel.py`. |
| `user_deprovisioning.py`     | Revokes sessions and deletes a user in Graph during delete lifecycle path.                          | `workflows/iam_onboarding.py`.                                              |

Parent orchestration in `workflows/` delegates focused subroutines to this folder to keep parent workflows smaller and easier to reason about. Each child workflow relies on activities in `activities/` for side effects and shared models from `shared/`. Worker queue binding happens in `workers/run_worker.py`.

## How To Run

Child workflows run through the same worker process:

```bash
python -m workers.run_worker
```

## How To Verify

Use standard test execution for child-workflow coverage:

```bash
python -m pytest -q
```

## Troubleshooting

- Child workflow IDs are often derived from event metadata for idempotent starts; preserve deterministic ID construction when extending.
- Keep child workflow interfaces model-based so parent and child boundaries are strongly typed.
- Timeout and signal behavior in `hitl_approval.py` is critical for SOC automation paths and should be covered when adding new actions.
