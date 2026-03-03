#!/bin/bash
# ──────────────────────────────────────────────────────────────
# Worker Startup Script — Temporal Worker Bootstrap
# ──────────────────────────────────────────────────────────────
# This script runs on first boot of the EC2 worker instance.
# It installs dependencies, pulls the worker container, and
# starts the Temporal worker process.
#
# Template variables (injected by Terraform):
#   ${db_endpoint}  — RDS PostgreSQL endpoint
#   ${db_name}      — Database name
#   ${db_username}  — Database username
#   ${environment}  — Environment name (poc/staging/prod)
# ──────────────────────────────────────────────────────────────

set -euo pipefail

exec > >(tee /var/log/worker-startup.log) 2>&1
echo "=== Worker startup script began at $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="

# ── System Updates ───────────────────────────────────────────
echo "[1/5] Installing system dependencies..."
dnf update -y -q
dnf install -y -q docker python3.11 python3.11-pip jq

# ── Start Docker ─────────────────────────────────────────────
echo "[2/5] Starting Docker daemon..."
systemctl enable docker
systemctl start docker

# ── Authenticate to ECR ──────────────────────────────────────
echo "[3/5] Authenticating to ECR..."
ACCOUNT_ID=$(curl -s http://169.254.169.254/latest/meta-data/identity-credentials/ec2/info | jq -r '.AccountId // empty')
REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)

if [ -n "$ACCOUNT_ID" ]; then
  aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com"
fi

# ── Configure Environment ────────────────────────────────────
echo "[4/5] Writing worker configuration..."
mkdir -p /opt/secamo

cat > /opt/secamo/.env <<EOF
ENVIRONMENT=${environment}
DB_ENDPOINT=${db_endpoint}
DB_NAME=${db_name}
DB_USERNAME=${db_username}
AWS_REGION=$REGION

# Temporal connection (populated from SSM at runtime)
# TEMPORAL_ADDRESS=
# TEMPORAL_NAMESPACE=
# TEMPORAL_TLS_CERT=
# TEMPORAL_TLS_KEY=
EOF

# ── Start Worker ─────────────────────────────────────────────
echo "[5/5] Starting Temporal worker..."

# TODO: Replace with actual container pull + run once CI/CD is configured
# docker pull $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/secamo-worker:latest
# docker run -d --restart=always --env-file /opt/secamo/.env \
#   --name secamo-worker \
#   $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/secamo-worker:latest

echo "=== Worker startup script completed at $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "NOTE: Worker container start is commented out — enable after CI/CD pipeline is ready."
