---
name: temporal-activity-audit
description: 'Review or generate Python Temporal activities with strict MCP-grounded standards. Use when auditing idempotency, retry safety, client initialization, error translation, timeouts/heartbeats, outbound auth, or when asked to harden activity implementations against Temporal and integration best practices.'
---

# Temporal Activity Audit

Use this skill to create or audit Temporal Activities with official documentation as the source of truth.

## When to Use This Skill

- User asks to create, improve, or review Temporal activity code
- User asks for retry safety, idempotency, or non-retryable error handling
- User asks to validate AWS/API integration behavior inside activities
- User asks for production-readiness checks on activity implementations

## Ground Truth Policy

- Treat MCP documentation as authoritative over model memory
- Before code generation or review, query relevant MCP sources for each dependency touched
- If MCP coverage is missing for a required dependency, state the gap explicitly before using general knowledge

Default lookup order:
1. Temporal workflows, activities, workers, SDK constraints: `temporal-mcp`
2. Microsoft Graph, Defender, Azure AD, M365 APIs: `microsoft-learn` docs tools
3. Third-party Python library behavior: `context7` (or equivalent package docs MCP)

## Activity Core Checklist

Query MCP before answering each item.

1. Idempotency
- Is the activity safe to retry without duplicate unsafe side effects?
- Are duplicate external actions prevented or safely deduplicated?

2. Client initialization
- Are external clients (boto3, HTTP sessions, DB connections) initialized outside activity functions for reuse?
- Is connection setup avoided on every retry execution?

3. Error translation
- Are vendor exceptions translated into Temporal-safe outcomes?
- Are 400/401-style caller errors marked non-retryable (for example via `ApplicationError` with non-retryable semantics)?
- Are 5xx/transient failures allowed to retry?

4. Timeouts and heartbeats
- Are cancellations/timeouts respected?
- For long-running outbound operations, are heartbeats and progress checkpoints implemented per SDK guidance?

5. Outbound auth
- Are secrets referenced securely (no hardcoded credentials)?
- Are outbound auth and request signing/headers implemented exactly as API docs require?

## Output Contract

Choose format based on task type.

### Code generation mode

- Write optimized Python code directly
- Add brief inline comments citing the MCP source used for framework-critical rules
- Keep implementation deterministic where required and retry-safe for activity semantics

### Code review mode

- Output violations only as dense bullets
- Required format per bullet:
  - `[Severity] - Description -> Actionable Fix (Cite MCP Source)`
- No intro/outro text

### Perfect result sentinel

If there are no deviations in review mode, output exactly:

Activity is production-ready. No deviations found.

## Quality Gates Before Finalizing

- Every finding or code decision is traceable to a cited MCP source
- Retry and failure-mode behavior is explicit
- Non-retryable vs retryable boundaries are unambiguous
- Security-sensitive behavior (auth/secrets) is explicitly verified
- Response contains zero fluff

## Example User Prompts

- "Audit `activities/graph_users.py` for Temporal retry safety and error translation."
- "Generate a production-safe activity that writes to DynamoDB with proper retry classification."
- "Review this activity for heartbeat and cancellation handling against Temporal SDK docs."