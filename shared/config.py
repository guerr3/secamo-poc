import os
from dotenv import load_dotenv

load_dotenv()

# ── Temporal Cloud verbindingsparameters ──────────────────────
TEMPORAL_ADDRESS = os.environ.get("TEMPORAL_ADDRESS", "temporal:7233")
TEMPORAL_NAMESPACE = os.environ.get("TEMPORAL_NAMESPACE", "default")
TEMPORAL_API_KEY   = os.environ.get("TEMPORAL_API_KEY", "")

# ── Microsoft Graph credentials VERWIJDERD ────────────────────
# Credentials worden nu dynamisch opgehaald via AWS Parameter Store 
# in de activities (bijv. get_tenant_secrets) op basis van tenant_id.

# ── Task Queue namen per domein ───────────────────────────────
QUEUE_IAM    = "iam-graph"
QUEUE_SOC    = "soc-defender"
QUEUE_AUDIT  = "audit"
