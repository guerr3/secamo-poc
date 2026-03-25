import os
import logging
import boto3
from typing import Dict, Any, Optional

# Configure logging
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)

TENANT_TABLE_NAME = os.environ.get("TENANT_TABLE_NAME", "").strip()
_dynamo = boto3.client("dynamodb")

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

def extract_tenant_header(event: Dict[str, Any]) -> Optional[str]:
    """Extract tenant identifier from request headers."""
    headers = {k.lower(): v for k, v in event.get("headers", {}).items() if v}
    return headers.get("x-tenant-id")


def _attribute_to_str(item: Dict[str, Dict[str, str]], name: str) -> str:
    attr = item.get(name) or {}
    if "S" in attr:
        return str(attr["S"])
    if "N" in attr:
        return str(attr["N"])
    if "BOOL" in attr:
        return "true" if bool(attr["BOOL"]) else "false"
    return ""


def _attribute_to_bool(item: Dict[str, Dict[str, str]], name: str) -> Optional[bool]:
    attr = item.get(name) or {}
    if "BOOL" in attr:
        return bool(attr["BOOL"])
    if "S" in attr:
        return str(attr["S"]).strip().lower() in {"1", "true", "yes", "on", "active", "enabled"}
    if "N" in attr:
        return str(attr["N"]).strip() == "1"
    return None


def _tenant_is_active(item: Dict[str, Dict[str, str]]) -> bool:
    explicit_active = _attribute_to_bool(item, "active")
    if explicit_active is not None:
        return explicit_active

    explicit_is_active = _attribute_to_bool(item, "is_active")
    if explicit_is_active is not None:
        return explicit_is_active

    status = _attribute_to_str(item, "status").strip().lower()
    if status:
        return status in {"active", "enabled", "true", "1"}

    # Default to inactive when no explicit activation markers are present.
    return False


def _lookup_tenant_item(tenant_id: str) -> Optional[Dict[str, Dict[str, str]]]:
    if not TENANT_TABLE_NAME:
        logger.error("TENANT_TABLE_NAME is not configured")
        return None

    try:
        response = _dynamo.get_item(
            TableName=TENANT_TABLE_NAME,
            Key={"tenant_id": {"S": tenant_id}},
            ConsistentRead=True,
        )
    except Exception as exc:
        logger.error("Tenant lookup failed tenant_id=%s error=%s", tenant_id, str(exc))
        return None

    item = response.get("Item")
    if not isinstance(item, dict):
        return None
    return item

def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    API Gateway Lambda Authorizer Handler (REQUEST type)
    """
    logger.debug("Authorizer invoked with event: %s", event)
    
    method_arn = event.get("methodArn", "")
    if not method_arn:
        logger.error("Missing methodArn in event")
        raise Exception("Unauthorized")

    tenant_id = (extract_tenant_header(event) or "").strip()
    if not tenant_id:
        logger.warning("Missing required x-tenant-id header")
        return generate_policy("anonymous", "Deny", method_arn)

    tenant_item = _lookup_tenant_item(tenant_id)
    if tenant_item is None:
        logger.warning("Tenant lookup returned no record tenant_id=%s", tenant_id)
        return generate_policy(tenant_id, "Deny", method_arn)

    if not _tenant_is_active(tenant_item):
        logger.warning("Tenant is not active tenant_id=%s", tenant_id)
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
