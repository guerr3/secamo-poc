import os
from dotenv import load_dotenv

load_dotenv()

# ── Temporal Cloud verbindingsparameters ──────────────────────
TEMPORAL_ADDRESS   = os.environ["TEMPORAL_ADDRESS"]
TEMPORAL_NAMESPACE = os.environ["TEMPORAL_NAMESPACE"]
TEMPORAL_API_KEY   = os.environ.get("TEMPORAL_API_KEY", "")

# ── Microsoft Graph — Legacy Sandbox (Removed) ────────────────
# Graph credentials are now dynamically fetched via SSM Parameter Store.

# ── Task Queue namen per domein ───────────────────────────────
QUEUE_IAM    = "iam-graph"
QUEUE_SOC    = "soc-defender"
QUEUE_AUDIT  = "audit"
