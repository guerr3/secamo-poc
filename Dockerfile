# ──────────────────────────────────────────────────────────────
# Secamo Worker — Multi-stage Docker Image
# ──────────────────────────────────────────────────────────────

# Stage 1: Install dependencies
FROM python:3.11-slim AS builder

WORKDIR /build

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: Runtime image
FROM python:3.11-slim

LABEL maintainer="secamo"
LABEL description="Secamo Temporal Worker"

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY shared/ ./shared/
COPY activities/ ./activities/
COPY connectors/ ./connectors/
COPY graph_ingress/ ./graph_ingress/
COPY workflows/ ./workflows/
COPY workers/ ./workers/

# Non-root user for security
RUN useradd --create-home --shell /bin/bash worker && \
    chown -R worker:worker /app
USER worker

# Health check: verify Python can import the worker module
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "from workers.run_worker import main" || exit 1

ENTRYPOINT ["python", "-m", "workers.run_worker"]
