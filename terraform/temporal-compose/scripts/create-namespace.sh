#!/bin/sh
set -eu

NAMESPACE=${DEFAULT_NAMESPACE:-default}
TEMPORAL_ADDRESS=${TEMPORAL_ADDRESS:-temporal:7233}

# Extracted from workflow declarations:
# - TenantId (Keyword)
# - CaseType (Keyword)
# - Severity (Keyword)
# - HiTLStatus (Keyword)
REQUIRED_SEARCH_ATTRIBUTES="TenantId:Keyword CaseType:Keyword Severity:Keyword HiTLStatus:Keyword"

ensure_search_attribute() {
  attr_name="$1"
  attr_type="$2"

  set +e
  output=$(temporal operator search-attribute create \
    --namespace "$NAMESPACE" \
    --name "$attr_name" \
    --type "$attr_type" \
    --address "$TEMPORAL_ADDRESS" 2>&1)
  status=$?
  set -e

  if [ "$status" -eq 0 ]; then
    echo "Search attribute '$attr_name' created in namespace '$NAMESPACE'"
    return 0
  fi

  # Idempotent startup: ignore already-exists errors.
  if echo "$output" | grep -Eqi "already exists|already registered|is in use"; then
    echo "Search attribute '$attr_name' already exists in namespace '$NAMESPACE'"
    return 0
  fi

  echo "Failed to create search attribute '$attr_name' in namespace '$NAMESPACE'"
  echo "$output"
  return 1
}

echo "Waiting for Temporal server port to be available..."
nc -z -w 10 $(echo $TEMPORAL_ADDRESS | cut -d: -f1) $(echo $TEMPORAL_ADDRESS | cut -d: -f2)
echo 'Temporal server port is available'

echo 'Waiting for Temporal server to be healthy...'
max_attempts=12
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

echo "Ensuring required custom search attributes exist in namespace '$NAMESPACE'..."
for attribute in $REQUIRED_SEARCH_ATTRIBUTES; do
  attr_name=$(echo "$attribute" | cut -d: -f1)
  attr_type=$(echo "$attribute" | cut -d: -f2)
  ensure_search_attribute "$attr_name" "$attr_type"
done
echo "Required custom search attributes are ready in namespace '$NAMESPACE'"
