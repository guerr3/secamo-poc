"""HiTL token lifecycle utilities and DynamoDB-backed token persistence.

Responsibility: manage token creation and mark-as-used retention semantics for approval callbacks.
This module must not parse provider callback payloads or perform workflow signal dispatching.
"""

from __future__ import annotations

import os
import time
from typing import Any, Mapping, Protocol, runtime_checkable

import boto3
from botocore.exceptions import ClientError
from pydantic import BaseModel, ConfigDict, Field


HITL_TOKEN_TTL_ENV_VAR = "HITL_TOKEN_TTL_SECONDS"
DEFAULT_HITL_TOKEN_TTL_SECONDS = 900


def get_hitl_token_ttl_seconds(environment: Mapping[str, str] | None = None) -> int:
    """Resolve token TTL from environment using guarded integer parsing."""

    source = os.environ if environment is None else environment
    raw_value = str(source.get(HITL_TOKEN_TTL_ENV_VAR, str(DEFAULT_HITL_TOKEN_TTL_SECONDS))).strip()
    try:
        parsed = int(raw_value)
    except ValueError:
        return DEFAULT_HITL_TOKEN_TTL_SECONDS
    if parsed <= 0:
        return DEFAULT_HITL_TOKEN_TTL_SECONDS
    return parsed


class HitlTokenRecord(BaseModel):
    """Immutable token record contract persisted in DynamoDB."""

    model_config = ConfigDict()

    token: str
    workflow_id: str
    tenant_id: str
    reviewer_identity: str
    channel: str
    allowed_actions: tuple[str, ...] = ()
    created_at: int
    expires_at: int
    used: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


@runtime_checkable
class DynamoTokenClient(Protocol):
    """Subset of DynamoDB client contract used by the token store."""

    def put_item(self, **kwargs: Any) -> dict[str, Any]:
        """Persist one token record in DynamoDB."""

    def update_item(self, **kwargs: Any) -> dict[str, Any]:
        """Mutate token record state in DynamoDB."""


class DynamoDbHitlTokenStore:
    """DynamoDB-backed token persistence with retention-first update semantics."""

    def __init__(
        self,
        table_name: str,
        *,
        dynamo_client: DynamoTokenClient | None = None,
        environment: Mapping[str, str] | None = None,
        time_provider: callable | None = None,
        ttl_seconds: int | None = None,
        region_name: str = "eu-west-1",
    ) -> None:
        self._table_name = table_name
        self._dynamo = dynamo_client or boto3.client("dynamodb", region_name=region_name)
        self._time = time_provider or time.time
        self._ttl_seconds = ttl_seconds if ttl_seconds is not None else get_hitl_token_ttl_seconds(environment)

    def create_token(
        self,
        *,
        token: str,
        workflow_id: str,
        tenant_id: str,
        reviewer_identity: str,
        channel: str,
        allowed_actions: tuple[str, ...],
        metadata: dict[str, Any] | None = None,
    ) -> HitlTokenRecord:
        """Persist token record with expires_at based on HITL_TOKEN_TTL_SECONDS."""

        now_epoch = int(self._time())
        expires_at = now_epoch + self._ttl_seconds
        meta = {} if metadata is None else metadata

        item = {
            "token": {"S": token},
            "workflow_id": {"S": workflow_id},
            "tenant_id": {"S": tenant_id},
            "reviewer_identity": {"S": reviewer_identity},
            "channel": {"S": channel},
            "allowed_actions": {"SS": list(allowed_actions)},
            "used": {"BOOL": False},
            "created_at": {"N": str(now_epoch)},
            "expires_at": {"N": str(expires_at)},
            "metadata": {"S": str(meta)},
        }
        self._dynamo.put_item(TableName=self._table_name, Item=item)

        return HitlTokenRecord(
            token=token,
            workflow_id=workflow_id,
            tenant_id=tenant_id,
            reviewer_identity=reviewer_identity,
            channel=channel,
            allowed_actions=allowed_actions,
            created_at=now_epoch,
            expires_at=expires_at,
            used=False,
            metadata=meta,
        )

    def mark_token_used(self, token: str) -> dict[str, Any] | None:
        """Mark token as used and set used_at while retaining token record."""

        now_epoch = int(self._time())
        try:
            response = self._dynamo.update_item(
                TableName=self._table_name,
                Key={"token": {"S": token}},
                UpdateExpression="SET used = :used, used_at = :used_at",
                ConditionExpression="attribute_exists(#token) AND used = :unused AND expires_at > :now_epoch",
                ExpressionAttributeNames={"#token": "token"},
                ExpressionAttributeValues={
                    ":used": {"BOOL": True},
                    ":used_at": {"N": str(now_epoch)},
                    ":unused": {"BOOL": False},
                    ":now_epoch": {"N": str(now_epoch)},
                },
                ReturnValues="ALL_OLD",
            )
            return response.get("Attributes")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "ConditionalCheckFailedException":
                return None
            raise
