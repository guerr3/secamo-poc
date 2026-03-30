#!/bin/bash
# ──────────────────────────────────────────────────────────────
# Build script for the secamo-ingress Lambda Layer
# ──────────────────────────────────────────────────────────────
#
# Installs Python dependencies into the layer directory alongside
# the ingress_sdk package, and copies shared runtime subpackages.
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
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../../../.." && pwd)"

echo "── Installing dependencies into ${LAYER_DIR} ──"

pip install \
  temporalio \
  pydantic \
  PyJWT \
  --target "${LAYER_DIR}" \
  --platform manylinux2014_aarch64 \
  --implementation cp \
  --python-version 3.11 \
  --only-binary=:all: \
  --upgrade \
  --quiet

# Copy shared package into the layer so the proxy Lambda can import it
echo "Copying shared package into layer..."
SHARED_DST="${LAYER_DIR}/shared"
rm -rf "${SHARED_DST}"
mkdir -p "${SHARED_DST}"

# Keep explicit subpackage list so newly added shared modules are not missed.
SHARED_SUBDIRS=(
  "approval"
  "auth"
  "ingress"
  "models"
  "normalization"
  "providers"
  "routing"
  "temporal"
)

find "${REPO_ROOT}/shared" -maxdepth 1 -type f -name "*.py" -exec cp {} "${SHARED_DST}/" \;

for subdir in "${SHARED_SUBDIRS[@]}"; do
  if [ -d "${REPO_ROOT}/shared/${subdir}" ]; then
    cp -r "${REPO_ROOT}/shared/${subdir}" "${SHARED_DST}/${subdir}"
  else
    echo "WARNING: shared/${subdir} not found in repository"
  fi
done

# Validate that key shared files are synced byte-for-byte from repository source.
SYNC_FILES=(
  "config.py"
  "models/canonical.py"
  "models/mappers.py"
  "routing/defaults.py"
  "routing/registry.py"
)

for relpath in "${SYNC_FILES[@]}"; do
  src="${REPO_ROOT}/shared/${relpath}"
  dst="${SHARED_DST}/${relpath}"
  if [ ! -f "${src}" ] || [ ! -f "${dst}" ]; then
    echo "ERROR: Shared sync verification failed (missing file): ${relpath}"
    exit 1
  fi
  if ! cmp -s "${src}" "${dst}"; then
    echo "ERROR: Shared sync verification failed (drift detected): ${relpath}"
    exit 1
  fi
done

# Clean up unnecessary files to reduce layer size
find "${LAYER_DIR}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "${LAYER_DIR}" -type d -name "*.dist-info" -exec rm -rf {} + 2>/dev/null || true
find "${LAYER_DIR}" -type d -name "tests" -exec rm -rf {} + 2>/dev/null || true

echo "── Layer build complete ──"
echo "Contents: $(du -sh "${LAYER_DIR}" | cut -f1)"
echo "SDK modules: $(find "${LAYER_DIR}/ingress_sdk" -name '*.py' | wc -l) files"
echo "Shared modules: $(find "${LAYER_DIR}/shared" -name '*.py' | wc -l) files"
