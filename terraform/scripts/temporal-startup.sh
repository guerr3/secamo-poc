#!/bin/bash
# ──────────────────────────────────────────────────────────────
# Temporal Server + Worker Startup Script
# ──────────────────────────────────────────────────────────────
# This script runs on first boot of the EC2 instance.
# It installs Docker, clones the secamo-poc repo, copies the
# canonical terraform/temporal-compose assets, and launches the
# local stack (Temporal + worker).
#
# Template variables (injected by Terraform):
#   ${temporal_namespace}        — Namespace to create
#   ${github_repo_url}           — GitHub repo URL to clone
#   ${environment}               — Environment identifier (e.g. test)
#   ${region}                    — AWS region
#   ${evidence_bucket}           — S3 bucket for evidence artifacts
#   ${audit_table}               — DynamoDB table for audit records
#   ${processed_events_table}    — DynamoDB table for polling dedup
#   ${tenant_table}              — DynamoDB table for tenant metadata
#   ${hitl_token_table}          — DynamoDB table for HiTL approval tokens
#   ${secamo_sender_email}       — Sender email for notification activities
#   ${email_provider}            — Fallback connector provider for outbound email
# ──────────────────────────────────────────────────────────────

set -euo pipefail

exec > >(tee /var/log/temporal-startup.log) 2>&1
echo "=== Temporal startup script began at $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="

# ── System Updates & Docker Install ──────────────────────────
echo "[1/6] Installing Docker, Git, and required tools..."
dnf update -y -q
dnf install -y -q docker git jq

# Enable and start Docker
systemctl enable docker
systemctl start docker

# Install Docker Compose plugin
mkdir -p /usr/local/lib/docker/cli-plugins
COMPOSE_VERSION="v2.32.4"
curl -fsSL "https://github.com/docker/compose/releases/download/$${COMPOSE_VERSION}/docker-compose-linux-x86_64" \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

# Verify installation
docker compose version
echo "Docker and Docker Compose installed successfully"

# ── Clone Secamo Repo ────────────────────────────────────────
echo "[2/6] Cloning secamo-poc repo..."
REPO_DIR="/opt/secamo-poc"

if [ -d "$REPO_DIR/.git" ]; then
  echo "Repo already exists, updating..."
  cd "$REPO_DIR"
  git fetch --all --prune
  git reset --hard origin/HEAD
else
  git clone ${github_repo_url} "$REPO_DIR"
fi

# ── Sync Canonical Compose Assets ────────────────────────────
echo "[3/6] Syncing canonical terraform/temporal-compose assets..."
TEMPORAL_DIR="/opt/temporal-compose"
rm -rf "$TEMPORAL_DIR"
mkdir -p "$TEMPORAL_DIR"
cp -a "$REPO_DIR/terraform/temporal-compose/." "$TEMPORAL_DIR/"

if [ ! -f "$TEMPORAL_DIR/.env" ]; then
  echo "temporal-compose/.env missing in repo clone; generating baseline defaults..."
  cat > "$TEMPORAL_DIR/.env" <<'EOF'
COMPOSE_PROJECT_NAME=temporal
TEMPORAL_VERSION=1.29.1
TEMPORAL_ADMINTOOLS_VERSION=1.29.1-tctl-1.18.4-cli-1.5.0
TEMPORAL_UI_VERSION=2.34.0
POSTGRESQL_VERSION=16
EOF
fi

set_env_var() {
  key="$1"
  value="$2"
  file="$3"
  if grep -q "^$${key}=" "$file"; then
    sed -i "s|^$${key}=.*|$${key}=$${value}|" "$file"
  else
    printf "%s=%s\n" "$key" "$value" >> "$file"
  fi
}

# Compose-level environment values consumed by docker-compose.yml
set_env_var "TEMPORAL_NAMESPACE" "${temporal_namespace}" "$TEMPORAL_DIR/.env"
set_env_var "temporal_namespace" "${temporal_namespace}" "$TEMPORAL_DIR/.env"
set_env_var "ENVIRONMENT" "${environment}" "$TEMPORAL_DIR/.env"
set_env_var "AWS_REGION" "${region}" "$TEMPORAL_DIR/.env"
set_env_var "EVIDENCE_BUCKET_NAME" "${evidence_bucket}" "$TEMPORAL_DIR/.env"
set_env_var "AUDIT_TABLE_NAME" "${audit_table}" "$TEMPORAL_DIR/.env"
set_env_var "PROCESSED_EVENTS_TABLE_NAME" "${processed_events_table}" "$TEMPORAL_DIR/.env"

# Runtime env file mounted into secamo containers
cat > "$REPO_DIR/.env" <<EOF
ENVIRONMENT=${environment}
AWS_REGION=${region}
TEMPORAL_ADDRESS=temporal:7233
TEMPORAL_NAMESPACE=${temporal_namespace}
EVIDENCE_BUCKET_NAME=${evidence_bucket}
AUDIT_TABLE_NAME=${audit_table}
PROCESSED_EVENTS_TABLE_NAME=${processed_events_table}
TENANT_TABLE_NAME=${tenant_table}
HITL_TOKEN_TABLE=${hitl_token_table}
SECAMO_SENDER_EMAIL=${secamo_sender_email}
EMAIL_PROVIDER=${email_provider}
EOF

# ── Start Temporal Stack ─────────────────────────────────────
echo "[4/6] Starting Temporal infrastructure via docker compose..."
cd "$TEMPORAL_DIR"

# Start Temporal infra first (worker builds from the cloned repo)
docker compose up -d postgresql temporal-admin-tools temporal temporal-create-namespace temporal-ui

# ── Wait for initialization ──────────────────────────────────
echo "[5/6] Waiting for Temporal to become healthy..."
until docker inspect --format='{{.State.Health.Status}}' temporal 2>/dev/null | grep -q "^healthy$"; do
  echo "Temporal not healthy yet, waiting 10s..."
  sleep 10
done
echo "Temporal is healthy."

until docker inspect --format='{{.State.Status}}' temporal-create-namespace 2>/dev/null | grep -q "^exited$"; do
  echo "Namespace job still running, waiting 5s..."
  sleep 5
done

EXIT_CODE=$(docker inspect --format='{{.State.ExitCode}}' temporal-create-namespace 2>/dev/null)
if [ "$EXIT_CODE" != "0" ]; then
  echo "ERROR: temporal-create-namespace failed with exit code $EXIT_CODE"
  docker logs temporal-create-namespace
  exit 1
fi
echo "Namespace created successfully."

# ── Start Worker Container ───────────────────────────────────
echo "[6/6] Building and starting secamo-worker container..."
cd "$TEMPORAL_DIR"
docker compose up -d --build secamo-worker

echo ""
echo "=== Temporal startup script completed at $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "Temporal Server:  0.0.0.0:7233"
echo "Temporal UI:      0.0.0.0:8080"
echo "Namespace:        ${temporal_namespace}"
echo "Evidence Bucket:  ${evidence_bucket}"
echo "Audit Table:      ${audit_table}"
echo "Dedup Table:      ${processed_events_table}"
echo "Worker:           secamo-worker (running)"
echo ""
echo "View logs: cd /opt/temporal-compose && docker compose logs -f"
echo "Worker logs: docker logs -f secamo-worker"
