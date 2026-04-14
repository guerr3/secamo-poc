import os


# ── Temporal Cloud verbindingsparameters ──────────────────────
TEMPORAL_ADDRESS = os.environ.get("TEMPORAL_ADDRESS", "temporal:7233")
TEMPORAL_NAMESPACE = os.environ.get("TEMPORAL_NAMESPACE", "default")

# ── Microsoft Graph credentials VERWIJDERD ────────────────────
# Credentials worden nu dynamisch opgehaald via AWS Parameter Store 
# in de activities (bijv. get_tenant_secrets) op basis van tenant_id.

# ── Task Queue namen per domein ───────────────────────────────
QUEUE_USER_LIFECYCLE = "user-lifecycle"
QUEUE_EDR            = "edr"
QUEUE_TICKETING      = "ticketing"
QUEUE_INTERACTIONS   = "interactions"
QUEUE_AUDIT          = "audit"
QUEUE_POLLING        = "polling"

# ── Shared runtime settings ──────────────────────────────────
SECAMO_SENDER_EMAIL = os.environ.get("SECAMO_SENDER_EMAIL", "noreply@secamo.local")
EMAIL_PROVIDER = os.environ.get("EMAIL_PROVIDER", "")
EVIDENCE_BUCKET_NAME = os.environ.get("EVIDENCE_BUCKET_NAME", "")
AUDIT_TABLE_NAME = os.environ.get("AUDIT_TABLE_NAME", "")
