#!/bin/bash
# ──────────────────────────────────────────────────────────────
# Build script for the secamo-ingress Lambda Layer
# ──────────────────────────────────────────────────────────────
#
# Installs Python dependencies into the layer directory alongside
# the ingress_sdk package. The result can be zipped by Terraform's
# archive_file data source or packaged manually.
#
# Usage:
#   chmod +x build.sh
#   ./build.sh
#
# For cross-compilation (local dev → Lambda arm64):
#   docker run --rm -v "$PWD":/var/task public.ecr.aws/sam/build-python3.11:latest \
#     bash -c "cd /var/task && ./build.sh"
# ──────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAYER_DIR="${SCRIPT_DIR}/python"

echo "── Installing dependencies into ${LAYER_DIR} ──"

pip install \
  temporalio \
  --target "${LAYER_DIR}" \
  --platform manylinux2014_aarch64 \
  --implementation cp \
  --python-version 3.11 \
  --only-binary=:all: \
  --upgrade \
  --quiet

# Clean up unnecessary files to reduce layer size
find "${LAYER_DIR}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "${LAYER_DIR}" -type d -name "*.dist-info" -exec rm -rf {} + 2>/dev/null || true
find "${LAYER_DIR}" -type d -name "tests" -exec rm -rf {} + 2>/dev/null || true

echo "── Layer build complete ──"
echo "Contents: $(du -sh "${LAYER_DIR}" | cut -f1)"
echo "SDK modules: $(find "${LAYER_DIR}/ingress_sdk" -name '*.py' | wc -l) files"
