import os
from dotenv import load_dotenv

load_dotenv()

# ── Temporal Cloud verbindingsparameters ──────────────────────
TEMPORAL_ADDRESS   = os.environ["TEMPORAL_ADDRESS"]
TEMPORAL_NAMESPACE = os.environ["TEMPORAL_NAMESPACE"]
TEMPORAL_API_KEY   = os.environ.get("TEMPORAL_API_KEY", "")

# ── Microsoft Graph — Sandbox tenant 1 ───────────────────────
GRAPH_TENANT1_ID      = os.environ["GRAPH_TENANT1_ID"]
GRAPH_CLIENT1_ID      = os.environ["GRAPH_CLIENT1_ID"]
GRAPH_SECRET1_VALUE   = os.environ["GRAPH_SECRET1_VALUE"]
GRAPH_SECRET1_ID      = os.environ["GRAPH_SECRET1_ID"]

# ── Task Queue namen per domein ───────────────────────────────
QUEUE_IAM    = "iam-graph"
QUEUE_SOC    = "soc-defender"
QUEUE_AUDIT  = "audit"
