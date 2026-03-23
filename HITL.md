> DEPRECATED: This document is superseded by [activities/README.md](activities/README.md), [workflows/child/README.md](workflows/child/README.md), and [terraform/README.md](terraform/README.md).

# Secamo HiTL Module

## Overview

The HiTL module provides a workflow-agnostic approval pattern for Temporal workflows.

From a workflow author perspective, integration is intentionally simple:

1. Build a HiTLRequest model with business context.
2. Execute the request_hitl_approval activity.
3. Wait for the existing approve signal carrying ApprovalDecision.

Workflows do not handle token generation, URL construction, DynamoDB storage, channel dispatch, or ingress callback logic.

## Channel Architecture

```text
+---------------------------+
| Temporal Workflow (WF-XX) |
| - builds HiTLRequest      |
| - executes activity       |
| - waits on signal approve |
+-------------+-------------+
              |
              v
+------------------------------+
| activity: request_hitl_approval |
+------------------------------+
   |                     |
   v                     v
+----------------+   +---------------------------+
| Email channel  |   | Jira channel              |
| - token create |   | - label secamo-wf:<id>    |
| - DynamoDB put |   | - transition to pending   |
| - Graph send   |   | - Jira webhook callback   |
+--------+-------+   +-------------+-------------+
         |                           |
         v                           v
  GET /api/v1/hitl/respond      POST /api/v1/hitl/jira
         |                           |
         +-------------+-------------+
                       v
         temporal.signal_workflow("approve", ApprovalDecision)
```

## Workflow Adoption Pattern

Any workflow can adopt the module with the same 3-step pattern:

1. Build HiTLRequest
   - Include workflow_id from workflow.info().workflow_id
   - Add title, description, allowed_actions, reviewer_email, metadata
2. Execute request_hitl_approval
   - Pass tenant_id, HiTLRequest, graph secrets, optional jira secrets
3. Wait for signal approve
   - Reuse the existing signal handler and wait_condition timeout logic

## Post-Deploy Manual Steps

1. Copy terraform output hitl_respond_url and update SSM parameter /secamo-temporal-test/hitl/endpoint_base_url.
2. Configure Jira webhook target to POST to /api/v1/hitl/jira.
3. Set /secamo/tenants/test-tenant/hitl/jira_webhook_secret in SSM to match the Jira webhook secret.
4. Set soc_analyst_email in tenant config path /secamo/tenants/<tenant_id>/config/soc_analyst_email.

## Token Security Model

- Tokens are generated with cryptographically secure randomness.
- Each email approval token is one-time use.
- Token validity is TTL-enforced through DynamoDB expires_at.
- Ingress callback marks token used via a single atomic conditional UpdateItem.
- Replay or expired token usage returns HTTP 410.
- Token value is never fully logged; only masked previews are logged.

## Adding a New Delivery Channel

To add a new channel (for example Slack or PagerDuty), follow this extension path:

1. Add a new internal dispatcher in activities/hitl.py
   - Implement _dispatch_<channel>()
   - Register channel key in dispatch_map used by request_hitl_approval
2. Add a corresponding ingress callback route in terraform/modules/ingress/src/ingress/handler.py
   - Validate channel-specific callback auth
   - Build ApprovalDecision-compatible payload
   - Signal workflow approve
3. Add API Gateway + Terraform route wiring for the new callback endpoint
   - Route resources
   - Method + integration
   - Deployment triggers

No workflow file changes are required for new channels.
