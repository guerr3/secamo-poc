# Walkthrough — Secamo POC Full Project Structure

## Final File Tree

```
secamo-poc/
├── shared/
│   ├── __init__.py
│   ├── config.py          ← modified (env var fix + Graph vars)
│   └── models.py          ← modified (4 → 15 dataclasses)
├── activities/
│   ├── __init__.py
│   ├── tenant.py          ← modified (wired to real env vars)
│   ├── graph_users.py     ← unchanged (7 activities)
│   ├── graph_alerts.py    ← NEW (5 activities)
│   ├── ticketing.py       ← NEW (4 activities)
│   ├── notifications.py   ← NEW (3 activities)
│   └── audit.py           ← modified (+collect_evidence_bundle)
├── workflows/
│   ├── __init__.py                    ← NEW
│   ├── iam_onboarding.py             ← NEW (WF-01)
│   ├── defender_alert_enrichment.py   ← NEW (WF-02)
│   └── impossible_travel.py          ← NEW (WF-05)
└── workers/
    ├── __init__.py        ← NEW
    └── run_worker.py      ← NEW (multi-queue bootstrap)
```

## Changes Made

### Shared Layer
| File | Change |
|---|---|
| [models.py](file:///c:/Users/ghost/Documents/codebases/secamo-poc/shared/models.py) | Added 11 new dataclasses: [AlertData](file:///c:/Users/ghost/Documents/codebases/secamo-poc/shared/models.py#57-68), [DefenderAlertRequest](file:///c:/Users/ghost/Documents/codebases/secamo-poc/shared/models.py#70-76), [EnrichedAlert](file:///c:/Users/ghost/Documents/codebases/secamo-poc/shared/models.py#78-90), [ThreatIntelResult](file:///c:/Users/ghost/Documents/codebases/secamo-poc/shared/models.py#92-100), [RiskScore](file:///c:/Users/ghost/Documents/codebases/secamo-poc/shared/models.py#102-109), [TicketData](file:///c:/Users/ghost/Documents/codebases/secamo-poc/shared/models.py#111-121), [TicketResult](file:///c:/Users/ghost/Documents/codebases/secamo-poc/shared/models.py#123-129), [NotificationResult](file:///c:/Users/ghost/Documents/codebases/secamo-poc/shared/models.py#131-137), [ImpossibleTravelRequest](file:///c:/Users/ghost/Documents/codebases/secamo-poc/shared/models.py#143-152), [ApprovalDecision](file:///c:/Users/ghost/Documents/codebases/secamo-poc/shared/models.py#154-161), [EvidenceBundle](file:///c:/Users/ghost/Documents/codebases/secamo-poc/shared/models.py#163-171) |
| [config.py](file:///c:/Users/ghost/Documents/codebases/secamo-poc/shared/config.py) | Fixed `TENANT1_ID` → `GRAPH_TENANT1_ID`, added `GRAPH_CLIENT1_ID`, `GRAPH_SECRET1_VALUE`, `GRAPH_SECRET1_ID` |

### Activities (20+ activities total)
| File | Activities |
|---|---|
| [tenant.py](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/tenant.py) | [validate_tenant_context](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/tenant.py#19-33), [get_tenant_secrets](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/tenant.py#35-53) — now using real env vars |
| [graph_users.py](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/graph_users.py) | 7 activities (unchanged) |
| [graph_alerts.py](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/graph_alerts.py) | [graph_enrich_alert](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/graph_alerts.py#13-39), [graph_get_alerts](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/graph_alerts.py#41-72), [graph_isolate_device](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/graph_alerts.py#74-90), [threat_intel_lookup](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/graph_alerts.py#92-113), [calculate_risk_score](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/graph_alerts.py#115-162) |
| [ticketing.py](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/ticketing.py) | [ticket_create](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/ticketing.py#5-25), [ticket_update](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/ticketing.py#27-47), [ticket_close](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/ticketing.py#49-69), [ticket_get_details](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/ticketing.py#71-94) |
| [notifications.py](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/notifications.py) | [teams_send_notification](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/notifications.py#5-25), [teams_send_adaptive_card](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/notifications.py#27-47), [email_send](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/notifications.py#49-70) |
| [audit.py](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/audit.py) | [create_audit_log](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/audit.py#7-35), [collect_evidence_bundle](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/audit.py#37-62) |

### Workflows
| File | Workflow | Queue | Key Features |
|---|---|---|---|
| [iam_onboarding.py](file:///c:/Users/ghost/Documents/codebases/secamo-poc/workflows/iam_onboarding.py) | WF-01 | `iam-graph` | 4-way action branch, idempotency check, license assignment |
| [defender_alert_enrichment.py](file:///c:/Users/ghost/Documents/codebases/secamo-poc/workflows/defender_alert_enrichment.py) | WF-02 | `soc-defender` | Alert enrichment → risk scoring → ticket → Teams notification |
| [impossible_travel.py](file:///c:/Users/ghost/Documents/codebases/secamo-poc/workflows/impossible_travel.py) | WF-05 | `soc-defender` | HITL with signal-based approval, 4h timeout/escalation, Adaptive Card |

### Worker
| File | Description |
|---|---|
| [run_worker.py](file:///c:/Users/ghost/Documents/codebases/secamo-poc/workers/run_worker.py) | Concurrent workers on 3 queues, Temporal Cloud TLS + API key auth |

## Verification Results

| Check | Result |
|---|---|
| `import shared.models` + `shared.config` | ✅ |
| `import activities.*` (all 6 modules) | ✅ |
| AST parse all workflows + worker | ✅ |
| `from workers.run_worker import main` | ✅ |
