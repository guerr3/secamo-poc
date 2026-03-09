import os
import time
import logging
import hmac
import boto3
from typing import Dict, Any, Tuple, Optional

# Configure logging
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)

# Initialize SSM Client inside the global scope to reuse the connection pool across warm starts
ssm_client = boto3.client("ssm")

# Simple TTL Cache for SSM parameters
# Structure: { "parameter_name": {"value": "secret_string", "expires_at": timestamp_in_seconds} }
SSM_CACHE: Dict[str, Dict[str, Any]] = {}
CACHE_TTL_SECONDS = int(os.environ.get("CACHE_TTL_SECONDS", "300"))

def get_ssm_parameter(param_name: str) -> Optional[str]:
    """Fetch an SSM parameter securely, returning from the local TTL cache if valid."""
    current_time = time.time()
    
    # Check cache first
    cached_item = SSM_CACHE.get(param_name)
    if cached_item and current_time < cached_item.get("expires_at", 0):
        logger.debug("Cache hit for parameter: %s", param_name)
        return cached_item["value"]
    
    try:
        logger.info("Fetching SSM parameter from AWS: %s", param_name)
        response = ssm_client.get_parameter(Name=param_name, WithDecryption=True)
        secret_value = response["Parameter"]["Value"]
        
        # Update cache
        SSM_CACHE[param_name] = {
            "value": secret_value,
            "expires_at": current_time + CACHE_TTL_SECONDS
        }
        return secret_value
    except ssm_client.exceptions.ParameterNotFound:
        logger.error("SSM Parameter not found: %s", param_name)
        return None
    except Exception as e:
        logger.error("Failed to fetch SSM parameter %s: %s", param_name, str(e))
        return None

def generate_policy(principal_id: str, effect: str, resource: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Helper function to generate an IAM policy for the API Gateway Custom Authorizer."""
    policy: Dict[str, Any] = {
        "principalId": principal_id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": resource
                }
            ]
        }
    }
    if context:
        policy["context"] = context
    
    return policy

def extract_headers(event: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """Extract required headers dynamically handling different cases."""
    headers = {k.lower(): v for k, v in event.get("headers", {}).items() if v}
    tenant_id = headers.get("x-tenant-id")
    auth_token = headers.get("authorization") or headers.get("x-signature")
    
    return tenant_id, auth_token

def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    API Gateway Lambda Authorizer Handler (REQUEST type)
    """
    logger.debug("Authorizer invoked with event: %s", event)
    
    method_arn = event.get("methodArn", "")
    if not method_arn:
        logger.error("Missing methodArn in event")
        raise Exception("Unauthorized")

    # Extract headers
    tenant_id, auth_token = extract_headers(event)

    if not tenant_id or not auth_token:
        logger.warning("Missing required headers (x-tenant-id or authorization/x-signature)")
        return generate_policy("anonymous", "Deny", method_arn)

    tenant_id = tenant_id.strip()
    auth_token = auth_token.strip()

    # In case the token starts with "Bearer ", strip it.
    if auth_token.lower().startswith("bearer "):
        auth_token = auth_token[7:].strip()

    if not tenant_id or not auth_token:
        logger.warning("Empty tenant_id or auth_token provided")
        return generate_policy("anonymous", "Deny", method_arn)

    # Fetch configured webhook secret from SSM
    ssm_param_name = f"/secamo/tenants/{tenant_id}/api/webhook_secret"
    expected_secret = get_ssm_parameter(ssm_param_name)

    if not expected_secret:
        logger.warning("Webhook secret not found or accessible for tenant: %s", tenant_id)
        return generate_policy(tenant_id, "Deny", method_arn)

    # Validate using secure string comparison (timing-safe)
    if not hmac.compare_digest(auth_token.encode("utf-8"), expected_secret.encode("utf-8")):
        logger.warning("Invalid authorization token for tenant: %s", tenant_id)
        return generate_policy(tenant_id, "Deny", method_arn)

    logger.info("Successfully authenticated tenant: %s", tenant_id)
    
    # Clean up the ARN so the generated policy applies to the whole API stage
    # Format: arn:aws:execute-api:{region}:{account}:{api-id}/{stage}/{method}/{resource}
    arn_parts = method_arn.split(":")
    if len(arn_parts) >= 6:
        api_gw_arn = ":".join(arn_parts[:5])
        api_id_stage = arn_parts[5].split("/")
        api_id = api_id_stage[0]
        stage = api_id_stage[1] if len(api_id_stage) > 1 else "*"
        resource_arn = f"{api_gw_arn}:{api_id}/{stage}/*"
    else:
        resource_arn = method_arn

    # Inject the verified tenant ID into the request context
    auth_context = {
        "tenant_id": tenant_id
    }

    return generate_policy(tenant_id, "Allow", resource_arn, context=auth_context)
