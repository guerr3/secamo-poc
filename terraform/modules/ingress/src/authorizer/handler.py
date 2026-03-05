"""
Lambda Authorizer — Mock Multi-Tenancy

Returns a valid IAM Allow policy for all incoming requests,
injecting a hardcoded tenant_id into the authorizer context.

In production, this would validate tokens (e.g. JWT / API key)
and extract the real tenant_id from the token claims.
"""

import logging
import os

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)

# Mock tenant ID for development/testing
MOCK_TENANT_ID = "tenant-demo-001"


def handler(event, context):
    """
    Lambda Authorizer handler (REQUEST type).

    Returns an IAM policy document that allows invocation,
    with the tenant_id injected into the authorizer context
    so downstream Lambdas can read it from
    event["requestContext"]["authorizer"]["tenant_id"].
    """
    logger.info(
        "Authorizer invoked: methodArn=%s, sourceIp=%s",
        event.get("methodArn", "unknown"),
        event.get("requestContext", {}).get("identity", {}).get("sourceIp", "unknown"),
    )

    method_arn = event.get("methodArn", "")

    # Build the ARN prefix for the policy resource
    # Format: arn:aws:execute-api:{region}:{account}:{api-id}/{stage}/{method}/{resource}
    arn_parts = method_arn.split(":")
    api_gw_arn = ":".join(arn_parts[:5])
    api_id_stage = arn_parts[5].split("/")
    api_id = api_id_stage[0]
    stage = api_id_stage[1] if len(api_id_stage) > 1 else "*"

    # Allow all methods/resources on this API + stage
    resource_arn = f"{api_gw_arn}:{api_id}/{stage}/*"

    policy = {
        "principalId": MOCK_TENANT_ID,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": "Allow",
                    "Resource": resource_arn,
                }
            ],
        },
        "context": {
            "tenant_id": MOCK_TENANT_ID,
        },
    }

    logger.info("Authorizer response: principalId=%s, resource=%s", MOCK_TENANT_ID, resource_arn)

    return policy
