#!/bin/bash
# ──────────────────────────────────────────────────────────────
# Temporal Server + Worker Startup Script
# ──────────────────────────────────────────────────────────────
# This script runs on first boot of the EC2 instance.
# It installs Docker, starts the Temporal stack, clones the
# secamo-poc repo, builds the worker Docker image, and starts
# the worker alongside the Temporal containers.
#
# Template variables (injected by Terraform):
#   ${temporal_namespace}   — Namespace to create
#   ${github_repo_url}      — GitHub repo URL to clone
#   ${db_endpoint}          — PostgreSQL database endpoint (docker network alias)
#   ${db_name}              — Database name
#   ${db_username}          — Database username
#   ${environment}          — Environment identifier (e.g. test)
#   ${region}               — AWS region
# ──────────────────────────────────────────────────────────────

set -euo pipefail

exec > >(tee /var/log/temporal-startup.log) 2>&1
echo "=== Temporal startup script began at $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="

# ── System Updates & Docker Install ──────────────────────────
echo "[1/6] Installing Docker and Git..."
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

# ── Create Temporal Compose Directory ────────────────────────
echo "[2/6] Writing docker-compose files..."
TEMPORAL_DIR="/opt/temporal-compose"
mkdir -p "$TEMPORAL_DIR/dynamicconfig"
mkdir -p "$TEMPORAL_DIR/scripts"

# .env — version pins
cat > "$TEMPORAL_DIR/.env" <<'ENVEOF'
COMPOSE_PROJECT_NAME=temporal
TEMPORAL_VERSION=1.29.1
TEMPORAL_ADMINTOOLS_VERSION=1.29.1-tctl-1.18.4-cli-1.5.0
TEMPORAL_UI_VERSION=2.34.0
POSTGRESQL_VERSION=16
ENVEOF

# docker-compose.yml — PostgreSQL-only variant + secamo worker
cat > "$TEMPORAL_DIR/docker-compose.yml" <<'COMPOSEEOF'
services:
  postgresql:
    image: postgres:$${POSTGRESQL_VERSION}
    container_name: temporal-postgresql
    ports:
      - "5432:5432"
    environment:
      POSTGRES_PASSWORD: temporal
      POSTGRES_USER: temporal
    networks:
      - temporal-network
    volumes:
      - /var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U temporal"]
      interval: 5s
      timeout: 5s
      retries: 60
      start_period: 30s

  temporal-admin-tools:
    image: temporalio/admin-tools:$${TEMPORAL_ADMINTOOLS_VERSION}
    container_name: temporal-admin-tools
    restart: on-failure:6
    depends_on:
      postgresql:
        condition: service_healthy
    environment:
      - DB=postgres12
      - DB_PORT=5432
      - POSTGRES_USER=temporal
      - POSTGRES_PWD=temporal
      - POSTGRES_SEEDS=postgresql
      - SQL_PASSWORD=temporal
    networks:
      - temporal-network
    volumes:
      - ./scripts:/scripts
    entrypoint: ["/bin/sh"]
    command: /scripts/setup-postgres.sh

  temporal:
    image: temporalio/server:$${TEMPORAL_VERSION}
    container_name: temporal
    depends_on:
      temporal-admin-tools:
        condition: service_completed_successfully
    environment:
      - DB=postgres12
      - DB_PORT=5432
      - POSTGRES_USER=temporal
      - POSTGRES_PWD=temporal
      - POSTGRES_SEEDS=postgresql
      - BIND_ON_IP=0.0.0.0
      - DYNAMIC_CONFIG_FILE_PATH=config/dynamicconfig/development-sql.yaml
    networks:
      - temporal-network
    ports:
      - '7233:7233'
    volumes:
      - ./dynamicconfig:/etc/temporal/config/dynamicconfig
    healthcheck:
      test: ["CMD", "nc", "-z", "localhost", "7233"]
      interval: 5s
      timeout: 3s
      start_period: 30s
      retries: 60

  temporal-create-namespace:
    image: temporalio/admin-tools:$${TEMPORAL_ADMINTOOLS_VERSION}
    container_name: temporal-create-namespace
    restart: on-failure:5
    depends_on:
      temporal:
        condition: service_healthy
    environment:
      - TEMPORAL_ADDRESS=temporal:7233
      - DEFAULT_NAMESPACE=${temporal_namespace}
    networks:
      - temporal-network
    volumes:
      - ./scripts:/scripts
    entrypoint: ["/bin/sh"]
    command: /scripts/create-namespace.sh

  temporal-ui:
    container_name: temporal-ui
    depends_on:
      temporal:
        condition: service_healthy
    environment:
      - TEMPORAL_ADDRESS=temporal:7233
      - TEMPORAL_CORS_ORIGINS=http://localhost:3000
    image: temporalio/ui:$${TEMPORAL_UI_VERSION}
    networks:
      - temporal-network
    ports:
      - 8080:8080

  secamo-worker:
    container_name: secamo-worker
    build:
      context: /opt/secamo-poc
      dockerfile: Dockerfile
    depends_on:
      temporal:
        condition: service_healthy
      temporal-create-namespace:
        condition: service_completed_successfully
    env_file:
      - /opt/secamo-poc/.env
    environment:
      - TEMPORAL_ADDRESS=temporal:7233
      - TEMPORAL_NAMESPACE=${temporal_namespace}
    networks:
      - temporal-network
    restart: unless-stopped

networks:
  temporal-network:
    driver: bridge
    name: temporal-network
COMPOSEEOF

# dynamicconfig
cat > "$TEMPORAL_DIR/dynamicconfig/development-sql.yaml" <<'DCEOF'
limit.maxIDLength:
  - value: 255
    constraints: {}
system.forceSearchAttributesCacheRefreshOnRead:
  - value: true
    constraints: {}
DCEOF

# setup-postgres.sh
cat > "$TEMPORAL_DIR/scripts/setup-postgres.sh" <<'SETUPEOF'
#!/bin/sh
set -eu

echo 'Starting PostgreSQL schema setup...'
echo 'Waiting for PostgreSQL port to be available...'
nc -z -w 10 postgresql 5432
echo 'PostgreSQL port is available'

temporal-sql-tool --plugin postgres12 --ep postgresql -u temporal -p 5432 --db temporal create
temporal-sql-tool --plugin postgres12 --ep postgresql -u temporal -p 5432 --db temporal setup-schema -v 0.0
temporal-sql-tool --plugin postgres12 --ep postgresql -u temporal -p 5432 --db temporal update-schema -d /etc/temporal/schema/postgresql/v12/temporal/versioned

temporal-sql-tool --plugin postgres12 --ep postgresql -u temporal -p 5432 --db temporal_visibility create
temporal-sql-tool --plugin postgres12 --ep postgresql -u temporal -p 5432 --db temporal_visibility setup-schema -v 0.0
temporal-sql-tool --plugin postgres12 --ep postgresql -u temporal -p 5432 --db temporal_visibility update-schema -d /etc/temporal/schema/postgresql/v12/visibility/versioned

echo 'PostgreSQL schema setup complete'
SETUPEOF
chmod +x "$TEMPORAL_DIR/scripts/setup-postgres.sh"

# create-namespace.sh
cat > "$TEMPORAL_DIR/scripts/create-namespace.sh" <<'NSEOF'
#!/bin/sh
set -eu

NAMESPACE=$${DEFAULT_NAMESPACE:-default}
TEMPORAL_ADDRESS=$${TEMPORAL_ADDRESS:-temporal:7233}

echo "Waiting for Temporal server port to be available..."
nc -z -w 10 $(echo $TEMPORAL_ADDRESS | cut -d: -f1) $(echo $TEMPORAL_ADDRESS | cut -d: -f2)
echo 'Temporal server port is available'

echo 'Waiting for Temporal server to be healthy...'
max_attempts=3
attempt=0

until temporal operator cluster health --address $TEMPORAL_ADDRESS; do
  attempt=$((attempt + 1))
  if [ $attempt -ge $max_attempts ]; then
    echo "Server did not become healthy after $max_attempts attempts"
    exit 1
  fi
  echo "Server not ready yet, waiting... (attempt $attempt/$max_attempts)"
  sleep 5
done

echo "Server is healthy, creating namespace '$NAMESPACE'..."
temporal operator namespace describe -n $NAMESPACE --address $TEMPORAL_ADDRESS || temporal operator namespace create -n $NAMESPACE --address $TEMPORAL_ADDRESS
echo "Namespace '$NAMESPACE' created"
NSEOF
chmod +x "$TEMPORAL_DIR/scripts/create-namespace.sh"

# ── Clone Secamo Repo ────────────────────────────────────────
echo "[3/6] Cloning secamo-poc repo..."
REPO_DIR="/opt/secamo-poc"

git clone ${github_repo_url} "$REPO_DIR"

# Write worker .env with credentials injected by Terraform
cat > "$REPO_DIR/.env" <<WORKERENVEOF
# Temporal (internal Docker network)
TEMPORAL_ADDRESS=temporal:7233
TEMPORAL_NAMESPACE=${temporal_namespace}

# Workspace & Environment
ENVIRONMENT=${environment}
AWS_REGION=${region}

# Database (PostgreSQL container in the same network)
DB_ENDPOINT=${db_endpoint}
DB_NAME=${db_name}
DB_USERNAME=${db_username}
WORKERENVEOF

# ── Start Temporal Stack ─────────────────────────────────────
echo "[4/6] Starting Temporal via docker-compose..."
cd "$TEMPORAL_DIR"

# Start Temporal infra first (worker builds from the cloned repo)
docker compose up -d postgresql temporal-admin-tools temporal temporal-create-namespace temporal-ui

# ── Wait for initialization ──────────────────────────────────
echo "[5/6] Wachten tot Temporal healthy is en namespace aangemaakt is..."
until docker inspect --format='{{.State.Health.Status}}' temporal 2>/dev/null | grep -q "^healthy$"; do
  echo "  Temporal nog niet healthy, wacht 10s..."
  sleep 10
done
echo "  Temporal is healthy."

until docker inspect --format='{{.State.Status}}' temporal-create-namespace 2>/dev/null | grep -q "^exited$"; do
  echo "  Namespace nog niet aangemaakt, wacht 5s..."
  sleep 5
done
echo "  Namespace aangemaakt."


# ── Start Worker Container ───────────────────────────────────
echo "[6/6] Building and starting secamo-worker container..."
cd "$TEMPORAL_DIR"
docker compose up -d --build secamo-worker

echo ""
echo "=== Temporal startup script completed at $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "Temporal Server:  0.0.0.0:7233"
echo "Temporal UI:      0.0.0.0:8080"
echo "Namespace:        ${temporal_namespace}"
echo "Worker:           secamo-worker (running)"
echo ""
echo "View logs: cd /opt/temporal-compose && docker compose logs -f"
echo "Worker logs: docker logs -f secamo-worker"
