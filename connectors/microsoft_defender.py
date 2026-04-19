from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import ipaddress
import secrets
import string
from typing import Any
from urllib.parse import quote

import httpx

from connectors.base import BaseConnector
from connectors.errors import (
    ConnectorPermanentError,
    ConnectorTransientError,
    ConnectorUnsupportedActionError,
)
from shared.graph_client import get_defender_token, get_graph_token
from shared.models import (
    DefenderDetectionFindingEvent,
    DefenderSecuritySignalEvent,
    Envelope,
    VendorExtension,
)
from shared.models.mappers import build_connector_correlation, build_envelope


class MicrosoftGraphConnector(BaseConnector):
    """Microsoft Graph/Defender connector implementation."""

    _MAX_ATTEMPTS = 3
    _MIN_SUBSCRIPTION_MINUTES = 45
    _SECURITY_ALERT_SUBSCRIPTION_MAX_MINUTES = 43200

    _RESOURCE_CONFIG: dict[str, dict[str, Any]] = {
        "defender_alerts": {
            "path": "/security/alerts_v2",
            "occurred_field": "createdDateTime",
            "filter_field": "createdDateTime",
            "provider_event_type": "alert",
            "supports_orderby": False,
        },
        "entra_risky_users": {
            "path": "/identityProtection/riskyUsers",
            "occurred_field": "riskLastUpdatedDateTime",
            "filter_field": "riskLastUpdatedDateTime",
            "provider_event_type": "risky_user",
            "supports_orderby": False,
            "max_top": 500,
        },
        "entra_signin_logs": {
            "path": "/auditLogs/signIns",
            "occurred_field": "createdDateTime",
            "filter_field": "createdDateTime",
            "provider_event_type": "signin_log",
            "supports_orderby": False,
        },
        "intune_noncompliant_devices": {
            "path": "/deviceManagement/managedDevices",
            "occurred_field": "lastSyncDateTime",
            "filter_field": "lastSyncDateTime",
            "base_filter": "complianceState eq 'noncompliant'",
            "provider_event_type": "noncompliant_device",
            "supports_orderby": False,
        },
        "entra_audit_logs": {
            "path": "/auditLogs/directoryAudits",
            "occurred_field": "activityDateTime",
            "filter_field": "activityDateTime",
            "provider_event_type": "audit_log",
            "supports_orderby": False,
        },
    }

    @property
    def provider(self) -> str:
        return "microsoft_defender"

    @staticmethod
    def _retry_delay_seconds(retry_after_header: str | None, attempt: int) -> float:
        if retry_after_header:
            try:
                return max(0.0, float(retry_after_header))
            except ValueError:
                pass
        return float(min(2 ** (attempt - 1), 30))

    async def _request_with_retry(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        params: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
        timeout: float = 20.0,
    ) -> httpx.Response:
        last_error: Exception | None = None

        for attempt in range(1, self._MAX_ATTEMPTS + 1):
            try:
                # Open a new connection on each attempt to avoid sticky failures.
                async with httpx.AsyncClient(timeout=timeout) as client:
                    response = await client.request(
                        method=method,
                        url=url,
                        headers=headers,
                        params=params,
                        json=json,
                    )
            except httpx.RequestError as exc:
                last_error = exc
                if attempt == self._MAX_ATTEMPTS:
                    break
                await asyncio.sleep(self._retry_delay_seconds(None, attempt))
                continue

            if response.status_code in (429, 503):
                if attempt == self._MAX_ATTEMPTS:
                    raise ConnectorTransientError(
                        f"Graph request throttled/unavailable after retries: status={response.status_code} url={url}"
                    )
                await asyncio.sleep(self._retry_delay_seconds(response.headers.get("Retry-After"), attempt))
                continue

            if response.status_code in (400, 401, 403, 404):
                error_details = self._graph_error_details(response)
                raise ConnectorPermanentError(
                    f"Graph request rejected: status={response.status_code} url={url}{error_details}"
                )

            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                if 500 <= response.status_code < 600:
                    last_error = exc
                    if attempt == self._MAX_ATTEMPTS:
                        break
                    await asyncio.sleep(self._retry_delay_seconds(response.headers.get("Retry-After"), attempt))
                    continue
                error_details = self._graph_error_details(response)
                raise ConnectorPermanentError(
                    f"Graph request failed: status={response.status_code} url={url}{error_details}"
                ) from exc

            return response

        raise ConnectorTransientError(f"Graph request failed after retries: {url}") from last_error

    @staticmethod
    def _parse_iso_datetime(value: str | None) -> datetime | None:
        if not value:
            return None
        parsed = value
        if parsed.endswith("Z"):
            parsed = parsed[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(parsed)
        except ValueError:
            return None

    @staticmethod
    def _format_odata_datetime(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _escape_odata_literal(value: str) -> str:
        return value.replace("'", "''")

    @staticmethod
    def _connector_error_status(error: Exception) -> int | None:
        text = str(error)
        marker = "status="
        if marker not in text:
            return None
        suffix = text.split(marker, 1)[1]
        digits = []
        for char in suffix:
            if char.isdigit():
                digits.append(char)
            else:
                break
        if not digits:
            return None
        try:
            return int("".join(digits))
        except ValueError:
            return None

    @staticmethod
    def _graph_error_details(response: httpx.Response) -> str:
        try:
            body = response.json()
        except ValueError:
            return ""
        if not isinstance(body, dict):
            return ""

        error = body.get("error")
        if not isinstance(error, dict):
            return ""

        code = str(error.get("code") or "").strip()
        message = str(error.get("message") or "").strip()
        parts: list[str] = []
        if code:
            parts.append(f"code={code}")
        if message:
            parts.append(f"message={message}")
        return f" ({', '.join(parts)})" if parts else ""

    @staticmethod
    def _generate_password(length: int = 16) -> str:
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return "".join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def _coerce_bool(value: Any) -> bool | None:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"true", "1", "yes", "y"}:
                return True
            if normalized in {"false", "0", "no", "n"}:
                return False
        return None

    @classmethod
    def _build_graph_create_user_body(cls, user_data: dict[str, Any]) -> dict[str, Any]:
        user_principal_name = cls._first_non_empty_str(
            user_data.get("userPrincipalName"),
            user_data.get("upn"),
            user_data.get("email"),
            user_data.get("user_email"),
        )
        if not user_principal_name:
            raise ConnectorUnsupportedActionError("create_user requires payload.user_data.email")

        display_name = cls._first_non_empty_str(
            user_data.get("displayName"),
            user_data.get("display_name"),
        )
        if not display_name:
            first_name = cls._first_non_empty_str(user_data.get("first_name"), user_data.get("givenName"))
            last_name = cls._first_non_empty_str(user_data.get("last_name"), user_data.get("surname"))
            display_name = f"{first_name or ''} {last_name or ''}".strip() or user_principal_name

        mail_nickname = cls._first_non_empty_str(
            user_data.get("mailNickname"),
            user_data.get("mail_nickname"),
        )
        if not mail_nickname:
            mail_nickname = user_principal_name.split("@", 1)[0]

        password = cls._first_non_empty_str(
            user_data.get("temp_password"),
            user_data.get("password"),
        ) or cls._generate_password()

        force_change_password = cls._coerce_bool(
            user_data.get("force_change_password_next_sign_in")
        )
        if force_change_password is None:
            force_change_password = cls._coerce_bool(user_data.get("forceChangePasswordNextSignIn"))
        if force_change_password is None:
            force_change_password = True

        account_enabled = cls._coerce_bool(user_data.get("account_enabled"))
        if account_enabled is None:
            account_enabled = cls._coerce_bool(user_data.get("accountEnabled"))
        if account_enabled is None:
            account_enabled = True

        body: dict[str, Any] = {
            "accountEnabled": account_enabled,
            "displayName": display_name,
            "mailNickname": mail_nickname,
            "userPrincipalName": user_principal_name,
            "passwordProfile": {
                "forceChangePasswordNextSignIn": force_change_password,
                "password": password,
            },
        }

        optional_string_fields = {
            "companyName": ("companyName", "company_name"),
            "givenName": ("givenName", "first_name"),
            "surname": ("surname", "last_name"),
            "department": ("department",),
            "jobTitle": ("jobTitle", "job_title", "role"),
            "officeLocation": ("officeLocation", "office_location"),
            "usageLocation": ("usageLocation", "usage_location"),
            "mobilePhone": ("mobilePhone", "mobile_phone"),
            "employeeId": ("employeeId", "employee_id"),
        }
        for target_field, source_fields in optional_string_fields.items():
            value = cls._first_non_empty_str(*(user_data.get(field) for field in source_fields))
            if value is not None:
                body[target_field] = value

        return body

    @classmethod
    def _normalize_graph_user_updates(cls, updates: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(updates, dict):
            return {}

        normalized: dict[str, Any] = {}

        direct_string_fields = {
            "displayName",
            "givenName",
            "surname",
            "department",
            "jobTitle",
            "companyName",
            "officeLocation",
            "mobilePhone",
            "usageLocation",
            "mailNickname",
            "employeeId",
        }
        for field_name in direct_string_fields:
            value = cls._coerce_non_empty_str(updates.get(field_name))
            if value is not None:
                normalized[field_name] = value

        alias_string_fields = {
            "display_name": "displayName",
            "first_name": "givenName",
            "given_name": "givenName",
            "last_name": "surname",
            "job_title": "jobTitle",
            "role": "jobTitle",
            "company_name": "companyName",
            "office_location": "officeLocation",
            "mobile_phone": "mobilePhone",
            "usage_location": "usageLocation",
            "mail_nickname": "mailNickname",
            "employee_id": "employeeId",
        }
        for source_field, target_field in alias_string_fields.items():
            if target_field in normalized:
                continue
            value = cls._coerce_non_empty_str(updates.get(source_field))
            if value is not None:
                normalized[target_field] = value

        account_enabled = cls._coerce_bool(updates.get("accountEnabled"))
        if account_enabled is None:
            account_enabled = cls._coerce_bool(updates.get("account_enabled"))
        if account_enabled is not None:
            normalized["accountEnabled"] = account_enabled

        if isinstance(updates.get("passwordProfile"), dict):
            normalized["passwordProfile"] = updates["passwordProfile"]
        else:
            temp_password = cls._first_non_empty_str(updates.get("temp_password"), updates.get("password"))
            if temp_password is not None:
                force_change_password = cls._coerce_bool(
                    updates.get("force_change_password_next_sign_in")
                )
                if force_change_password is None:
                    force_change_password = cls._coerce_bool(updates.get("forceChangePasswordNextSignIn"))
                if force_change_password is None:
                    force_change_password = True
                normalized["passwordProfile"] = {
                    "forceChangePasswordNextSignIn": force_change_password,
                    "password": temp_password,
                }

        return normalized

    @classmethod
    def _normalize_subscription_resource(cls, resource: str) -> str:
        normalized = resource.strip()
        lowered = normalized.lower().lstrip("/")
        if lowered.startswith("security/alerts_v2"):
            suffix = normalized.lstrip("/")[len("security/alerts_v2"):]
            normalized = f"security/alerts{suffix}"
        return normalized

    @classmethod
    def _max_subscription_minutes_for_resource(cls, resource: str) -> int | None:
        normalized = resource.strip().lower().lstrip("/")
        if normalized.startswith("security/alerts"):
            return cls._SECURITY_ALERT_SUBSCRIPTION_MAX_MINUTES
        return None

    @classmethod
    def _clamp_subscription_minutes(cls, *, requested_minutes: int, resource: str) -> int:
        bounded_minutes = max(requested_minutes, cls._MIN_SUBSCRIPTION_MINUTES)
        max_minutes = cls._max_subscription_minutes_for_resource(resource)
        if max_minutes is not None:
            bounded_minutes = min(bounded_minutes, max_minutes)
        return bounded_minutes

    @staticmethod
    def _coerce_non_empty_str(value: Any) -> str | None:
        if isinstance(value, str):
            stripped = value.strip()
            return stripped or None
        return None

    @classmethod
    def _first_non_empty_str(cls, *values: Any) -> str | None:
        for value in values:
            candidate = cls._coerce_non_empty_str(value)
            if candidate is not None:
                return candidate
        return None

    @staticmethod
    def _is_valid_ip(value: str | None) -> bool:
        if not value:
            return False
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    @classmethod
    def _extract_alert_evidence_fields(cls, item: dict[str, Any]) -> dict[str, str | None]:
        source_ip: str | None = None
        destination_ip: str | None = None
        device_id: str | None = None
        user_email: str | None = None

        evidence_items = item.get("evidence")
        if not isinstance(evidence_items, list):
            evidence_items = []

        for evidence in evidence_items:
            if not isinstance(evidence, dict):
                continue

            evidence_type = str(evidence.get("@odata.type") or "").lower()

            if "ipevidence" in evidence_type:
                ip_candidate = cls._first_non_empty_str(
                    evidence.get("ipAddress"),
                    evidence.get("ipV4"),
                    evidence.get("ipV6"),
                    evidence.get("address"),
                )
                if source_ip is None and cls._is_valid_ip(ip_candidate):
                    source_ip = ip_candidate
                continue

            if "networkconnectionevidence" in evidence_type:
                source_candidate = cls._first_non_empty_str(
                    evidence.get("sourceAddress"),
                    evidence.get("sourceIpAddress"),
                    evidence.get("ipAddress"),
                )
                destination_candidate = cls._first_non_empty_str(
                    evidence.get("destinationAddress"),
                    evidence.get("destinationIpAddress"),
                )
                if source_ip is None and cls._is_valid_ip(source_candidate):
                    source_ip = source_candidate
                if destination_ip is None and cls._is_valid_ip(destination_candidate):
                    destination_ip = destination_candidate
                continue

            if "deviceevidence" in evidence_type:
                device_candidate = cls._first_non_empty_str(
                    evidence.get("deviceId"),
                    evidence.get("mdeDeviceId"),
                    evidence.get("azureAdDeviceId"),
                    evidence.get("aadDeviceId"),
                )
                if device_id is None and device_candidate is not None:
                    device_id = device_candidate
                continue

            if "userevidence" in evidence_type:
                user_account = evidence.get("userAccount")
                user_candidate = cls._first_non_empty_str(
                    evidence.get("userPrincipalName"),
                    evidence.get("email"),
                    user_account.get("userPrincipalName") if isinstance(user_account, dict) else None,
                    user_account.get("emailAddress") if isinstance(user_account, dict) else None,
                )
                if user_email is None and user_candidate is not None:
                    user_email = user_candidate

        return {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "device_id": device_id,
            "user_email": user_email,
        }

    @classmethod
    def _alert_matches_user_email(cls, item: dict[str, Any], user_email: str) -> bool:
        normalized_user_email = user_email.strip().lower()
        if not normalized_user_email:
            return False

        direct_candidates = (
            cls._coerce_non_empty_str(item.get("userPrincipalName")),
            cls._coerce_non_empty_str(item.get("userEmail")),
            cls._coerce_non_empty_str(item.get("assignedTo")),
        )
        if any(candidate and candidate.lower() == normalized_user_email for candidate in direct_candidates):
            return True

        evidence_email = cls._coerce_non_empty_str(cls._extract_alert_evidence_fields(item).get("user_email"))
        if evidence_email and evidence_email.lower() == normalized_user_email:
            return True

        user_states = item.get("userStates")
        if not isinstance(user_states, list):
            return False

        for user_state in user_states:
            if not isinstance(user_state, dict):
                continue
            state_email = cls._first_non_empty_str(
                user_state.get("userPrincipalName"),
                user_state.get("emailAddress"),
                user_state.get("upn"),
            )
            if state_email and state_email.lower() == normalized_user_email:
                return True
        return False

    async def _fetch_user_alerts(self, *, headers: dict[str, str], user_email: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
        max_top = min(max(int(payload.get("top", 100)), 1), 200)
        since_hours = min(max(int(payload.get("since_hours", 24)), 1), 24 * 30)
        since_dt = datetime.now(timezone.utc) - timedelta(hours=since_hours)

        url = "https://graph.microsoft.com/v1.0/security/alerts_v2"
        params = {
            "$top": str(max_top),
            "$filter": f"createdDateTime gt {self._format_odata_datetime(since_dt)}",
        }
        if bool(payload.get("include_evidence", False)):
            params["$expand"] = "evidence"

        response = await self._request_defender_alerts_with_fallback(
            url=url,
            headers=headers,
            params=params,
            allow_drop_expand=bool(payload.get("include_evidence", False)),
        )

        body = response.json()
        alerts = [
            item
            for item in body.get("value", [])
            if isinstance(item, dict) and self._alert_matches_user_email(item, user_email)
        ]
        return alerts[:max_top]

    async def _request_defender_alerts_with_fallback(
        self,
        *,
        url: str,
        headers: dict[str, str],
        params: dict[str, str] | None,
        allow_drop_expand: bool = False,
    ) -> httpx.Response:
        if params is None:
            return await self._request_with_retry("GET", url, headers=headers, params=None)

        attempts: list[dict[str, str] | None] = [dict(params)]
        if allow_drop_expand and "$expand" in params:
            attempts.append(
                {
                    key: value
                    for key, value in params.items()
                    if key != "$expand"
                }
            )

        seen_keys: set[tuple[tuple[str, str], ...]] = set()
        deduped_attempts: list[dict[str, str] | None] = []
        for candidate in attempts:
            candidate = candidate or None
            key = tuple(sorted(candidate.items())) if candidate else tuple()
            if key in seen_keys:
                continue
            seen_keys.add(key)
            deduped_attempts.append(candidate)

        last_error: ConnectorPermanentError | None = None
        for candidate_params in deduped_attempts:
            try:
                return await self._request_with_retry(
                    "GET",
                    url,
                    headers=headers,
                    params=candidate_params,
                )
            except ConnectorPermanentError as exc:
                if self._connector_error_status(exc) != 400:
                    raise
                last_error = exc

        if last_error is not None:
            raise last_error
        raise ConnectorPermanentError(f"Graph request rejected: status=400 url={url}")

    @classmethod
    def _severity_from_signal(cls, item: dict[str, Any]) -> tuple[int, str]:
        raw = cls._first_non_empty_str(
            item.get("severity"),
            item.get("riskLevel"),
            item.get("riskLevelAggregated"),
            item.get("riskLevelDuringSignIn"),
            item.get("riskScore"),
            item.get("complianceState"),
        )
        normalized = (raw or "unknown").strip().lower()
        mapping = {
            "critical": 80,
            "high": 60,
            "medium": 40,
            "low": 20,
        }
        if normalized in {"noncompliant", "atrisk", "atrisk", "compromised"}:
            return 60, "high"
        if normalized in {"compliant", "none", "unknown", "informational"}:
            return 20, "low"
        return mapping.get(normalized, 30), (normalized if normalized in mapping else "medium")

    @classmethod
    def _status_from_signal(cls, item: dict[str, Any]) -> str | None:
        return cls._first_non_empty_str(
            item.get("status"),
            item.get("riskState"),
            item.get("complianceState"),
            item.get("result"),
            item.get("activityResult"),
        )

    @classmethod
    def _signal_title(
        cls,
        item: dict[str, Any],
        *,
        resource_type: str,
        provider_event_type: str,
        signal_id: str,
    ) -> str:
        candidate = cls._first_non_empty_str(
            item.get("title"),
            item.get("displayName"),
            item.get("activityDisplayName"),
            item.get("userPrincipalName"),
            item.get("userDisplayName"),
            item.get("deviceName"),
            item.get("id"),
        )
        if candidate is not None:
            return candidate
        suffix = signal_id or "signal"
        return f"{resource_type}:{provider_event_type}:{suffix}"

    @classmethod
    def _signal_description(cls, item: dict[str, Any]) -> str | None:
        return cls._first_non_empty_str(
            item.get("description"),
            item.get("riskDetail"),
            item.get("resultReason"),
            item.get("activityDisplayName"),
        )

    def _map_security_signal_event(
        self,
        *,
        item: dict[str, Any],
        resource_type: str,
        provider_event_type: str,
        occurred_at: datetime,
        external_id: str,
    ) -> DefenderSecuritySignalEvent:
        signal_id = external_id or f"{resource_type}:{provider_event_type}:{int(occurred_at.timestamp())}"
        severity_id, severity = self._severity_from_signal(item)
        status = self._status_from_signal(item)
        user_principal_name = self._first_non_empty_str(
            item.get("userPrincipalName"),
            item.get("userEmail"),
            item.get("email"),
            item.get("upn"),
            item.get("user", {}).get("userPrincipalName") if isinstance(item.get("user"), dict) else None,
            item.get("initiatedBy", {}).get("user", {}).get("userPrincipalName")
            if isinstance(item.get("initiatedBy"), dict)
            else None,
        )
        device_id = self._first_non_empty_str(
            item.get("deviceId"),
            item.get("azureADDeviceId"),
            item.get("azureAdDeviceId"),
            item.get("aadDeviceId"),
        )

        return DefenderSecuritySignalEvent(
            event_type="defender.security_signal",
            activity_id=2100,
            activity_name="poller.fetch",
            signal_id=signal_id,
            provider_event_type=provider_event_type,
            resource_type=resource_type,
            title=self._signal_title(
                item,
                resource_type=resource_type,
                provider_event_type=provider_event_type,
                signal_id=signal_id,
            ),
            description=self._signal_description(item),
            severity_id=severity_id,
            severity=severity,
            status=status,
            vendor_extensions={
                "provider_event_type": VendorExtension(source=self.provider, value=provider_event_type),
                "resource_type": VendorExtension(source=self.provider, value=resource_type),
                "user_email": VendorExtension(source=self.provider, value=user_principal_name),
                "user_principal_name": VendorExtension(
                    source=self.provider,
                    value=user_principal_name,
                ),
                "device_id": VendorExtension(source=self.provider, value=device_id),
                "entity_id": VendorExtension(
                    source=self.provider,
                    value=self._first_non_empty_str(item.get("id"), item.get("userId"), item.get("deviceId")),
                ),
            },
        )

    def _map_event(self, item: dict[str, Any], resource_type: str, occurred_field: str, provider_event_type: str) -> Envelope:
        occurred_at = self._parse_iso_datetime(item.get(occurred_field))
        if occurred_at is None:
            occurred_at = datetime.now(timezone.utc)
        external_id = str(item.get("id") or item.get("alertId") or "")

        if resource_type == "defender_alerts":
            evidence_fields = self._extract_alert_evidence_fields(item)
            payload = DefenderDetectionFindingEvent(
                event_type="defender.alert",
                activity_id=2004,
                activity_name="poller.fetch",
                alert_id=external_id,
                title=str(item.get("title") or external_id),
                description=str(item.get("description") or ""),
                severity_id=40,
                severity=(item.get("severity") or "medium").lower(),
                vendor_extensions={
                    "provider_event_type": VendorExtension(source=self.provider, value=provider_event_type),
                    "resource_type": VendorExtension(source=self.provider, value=resource_type),
                    "source_ip": VendorExtension(source=self.provider, value=evidence_fields["source_ip"]),
                    "destination_ip": VendorExtension(source=self.provider, value=evidence_fields["destination_ip"]),
                    "device_id": VendorExtension(source=self.provider, value=evidence_fields["device_id"]),
                    "user_email": VendorExtension(source=self.provider, value=evidence_fields["user_email"]),
                },
            )
        else:
            payload = self._map_security_signal_event(
                item=item,
                resource_type=resource_type,
                provider_event_type=provider_event_type,
                occurred_at=occurred_at,
                external_id=external_id,
            )

        correlation_id = external_id or f"{self.tenant_id}:{provider_event_type}:{int(occurred_at.timestamp())}"
        correlation = build_connector_correlation(
            tenant_id=self.tenant_id,
            event_name=payload.event_type,
            correlation_id=correlation_id,
            provider_event_id=external_id or "poll",
        )

        return build_envelope(
            tenant_id=self.tenant_id,
            source_provider=self.provider,
            occurred_at=occurred_at,
            payload=payload,
            correlation=correlation,
            provider_event_id=external_id or None,
            metadata={"provider_event_id": external_id, "resource_type": resource_type},
        )

    async def fetch_events(self, query: dict) -> list[Envelope]:
        token = await get_graph_token(self.secrets)
        top = int(query.get("top", 20))
        resource_type = str(query.get("resource_type", "defender_alerts")).strip().lower() or "defender_alerts"
        resource_config = self._RESOURCE_CONFIG.get(resource_type)
        if resource_config is None:
            raise ConnectorUnsupportedActionError(
                f"Unsupported resource_type '{resource_type}' for provider '{self.provider}'"
            )
        max_top = resource_config.get("max_top")
        if isinstance(max_top, int):
            top = min(top, max_top)

        since_raw = query.get("since")
        since_dt = self._parse_iso_datetime(str(since_raw)) if since_raw else None
        if since_dt is None:
            since_dt = datetime.now(timezone.utc) - timedelta(hours=24)

        filter_field = resource_config["filter_field"]
        since_filter = f"{filter_field} gt {self._format_odata_datetime(since_dt)}"

        base_filter = resource_config.get("base_filter")
        combined_filter = f"({base_filter}) and ({since_filter})" if base_filter else since_filter

        url = f"https://graph.microsoft.com/v1.0{resource_config['path']}"
        params = {
            "$top": str(top),
            "$filter": combined_filter,
        }
        if bool(resource_config.get("supports_orderby")):
            params["$orderby"] = f"{filter_field} asc"

        headers = {"Authorization": f"Bearer {token}"}
        events: list[Envelope] = []
        next_url: str | None = url
        next_params: dict[str, str] | None = params
        visited_urls: set[str] = set()
        while next_url:
            if next_url in visited_urls:
                break
            visited_urls.add(next_url)

            if resource_type == "defender_alerts":
                response = await self._request_defender_alerts_with_fallback(
                    url=next_url,
                    headers=headers,
                    params=next_params,
                )
            else:
                response = await self._request_with_retry(
                    "GET",
                    next_url,
                    headers=headers,
                    params=next_params,
                )
            payload = response.json()

            for item in payload.get("value", []):
                events.append(
                    self._map_event(
                        item=item,
                        resource_type=resource_type,
                        occurred_field=resource_config["occurred_field"],
                        provider_event_type=resource_config["provider_event_type"],
                    )
                )
            next_url = payload.get("@odata.nextLink")
            next_params = None
        return events

    async def execute_action(self, action: str, payload: dict) -> dict:
        if action == "enrich_alert_context":
            token = await get_graph_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}

            alert_id = str(payload.get("alert_id") or "").strip()
            severity = str(payload.get("severity") or "medium").lower()
            title = str(payload.get("title") or "")
            description = str(payload.get("description") or "")
            user_email = str(payload.get("user_email") or "").strip() or None
            device_id = str(payload.get("device_id") or "").strip() or None
            alert_body: dict[str, Any] = {}
            evidence_fields = {
                "source_ip": None,
                "destination_ip": None,
                "device_id": None,
                "user_email": None,
            }

            if alert_id:
                alert_url = f"https://graph.microsoft.com/v1.0/security/alerts_v2/{quote(alert_id)}"
                try:
                    alert_response = await self._request_with_retry("GET", alert_url, headers=headers)
                except ConnectorPermanentError as exc:
                    if self._connector_error_status(exc) != 404:
                        raise
                else:
                    alert_body = alert_response.json()
                    evidence_fields = self._extract_alert_evidence_fields(alert_body)
                    severity = str(alert_body.get("severity") or severity).lower()
                    title = str(alert_body.get("title") or title)
                    description = str(alert_body.get("description") or description)
                    if user_email is None:
                        user_email = evidence_fields["user_email"]
                    if device_id is None:
                        device_id = evidence_fields["device_id"]

            user_display_name = None
            user_department = None
            if user_email:
                user_url = f"https://graph.microsoft.com/v1.0/users/{quote(user_email)}?$select=displayName,department"
                try:
                    user_response = await self._request_with_retry("GET", user_url, headers=headers)
                    user_body = user_response.json()
                    user_display_name = user_body.get("displayName")
                    user_department = user_body.get("department")
                except ConnectorPermanentError as exc:
                    if self._connector_error_status(exc) != 404:
                        raise

            device_display_name = None
            device_os = None
            device_compliance = None
            if device_id:
                device_url = (
                    "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/"
                    f"{quote(device_id)}?$select=deviceName,operatingSystem,complianceState,isCompliant"
                )
                try:
                    device_response = await self._request_with_retry("GET", device_url, headers=headers)
                    device_body = device_response.json()
                    device_display_name = device_body.get("deviceName")
                    device_os = device_body.get("operatingSystem") or device_body.get("osPlatform")
                    compliance_state = str(device_body.get("complianceState") or "").lower()
                    if compliance_state in {"compliant", "noncompliant"}:
                        device_compliance = compliance_state
                    elif "isCompliant" in device_body:
                        device_compliance = "compliant" if bool(device_body.get("isCompliant")) else "noncompliant"
                except ConnectorPermanentError as exc:
                    # Some tenants return 400 for non-Intune device identifiers.
                    # Device lookup is enrichment-only, so keep best-effort behavior.
                    if self._connector_error_status(exc) not in {400, 404}:
                        raise

            return {
                "success": True,
                "provider": self.provider,
                "details": "alert context enriched",
                "alert_id": alert_id,
                "severity": severity,
                "title": title,
                "description": description,
                "user_display_name": user_display_name,
                "user_department": user_department,
                "device_display_name": device_display_name,
                "device_os": device_os,
                "device_compliance": device_compliance,
                "source_ip": evidence_fields["source_ip"] if alert_id else None,
                "destination_ip": evidence_fields["destination_ip"] if alert_id else None,
                "evidence": alert_body.get("evidence", []) if alert_id else [],
            }

        if action in {"list_user_alerts", "get_user_alerts"}:
            token = await get_graph_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}
            user_email = str(payload.get("user_email") or "").strip()
            if not user_email:
                raise ConnectorUnsupportedActionError("list_user_alerts requires payload.user_email")

            alerts = await self._fetch_user_alerts(headers=headers, user_email=user_email, payload=payload)
            return {
                "success": True,
                "provider": self.provider,
                "details": "alerts listed",
                "alerts": alerts,
            }

        if action == "list_risky_users":
            token = await get_graph_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}

            lookup_key = str(payload.get("lookup_key") or "").strip()
            min_risk_level = str(payload.get("min_risk_level") or "low").lower()
            risk_levels = ["low", "medium", "high"]
            if min_risk_level not in risk_levels:
                min_risk_level = "low"

            allowed = risk_levels[risk_levels.index(min_risk_level):]
            filter_parts = [f"riskLevel eq '{level}'" for level in allowed]
            if lookup_key and "@" in lookup_key:
                escaped_lookup = self._escape_odata_literal(lookup_key)
                filter_parts.append(f"userPrincipalName eq '{escaped_lookup}'")
            query_filter = " and ".join(["(" + " or ".join(filter_parts[:-1]) + ")", filter_parts[-1]]) if len(filter_parts) > 1 and lookup_key and "@" in lookup_key else " or ".join(filter_parts)

            if lookup_key and "@" not in lookup_key:
                url = f"https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/{quote(lookup_key)}"
                try:
                    response = await self._request_with_retry("GET", url, headers=headers)
                except ConnectorPermanentError as exc:
                    if self._connector_error_status(exc) == 404:
                        return {
                            "success": True,
                            "provider": self.provider,
                            "details": "risky users listed",
                            "users": [],
                        }
                    raise
                return {
                    "success": True,
                    "provider": self.provider,
                    "details": "risky users listed",
                    "users": [response.json()],
                }

            url = "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers"
            users: list[dict[str, Any]] = []
            next_url: str | None = url
            next_params: dict[str, str] | None = {"$filter": query_filter, "$top": "500"}
            while next_url and len(users) < 500:
                response = await self._request_with_retry("GET", next_url, headers=headers, params=next_params)
                body = response.json()
                users.extend(body.get("value", []))
                next_url = body.get("@odata.nextLink")
                next_params = None
            return {
                "success": True,
                "provider": self.provider,
                "details": "risky users listed",
                "users": users[:500],
            }

        if action == "get_signin_history":
            token = await get_graph_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}

            user_principal_name = str(payload.get("user_principal_name") or "").strip()
            if not user_principal_name:
                raise ConnectorUnsupportedActionError("get_signin_history requires payload.user_principal_name")

            top = min(max(int(payload.get("top", 20)), 1), 1000)
            escaped = self._escape_odata_literal(user_principal_name)
            signins: list[dict[str, Any]] = []

            next_url: str | None = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
            next_params: dict[str, str] | None = {
                "$filter": f"userPrincipalName eq '{escaped}'",
                "$top": str(min(top, 100)),
            }

            while next_url and len(signins) < top:
                response = await self._request_with_retry("GET", next_url, headers=headers, params=next_params)
                body = response.json()
                batch = body.get("value", [])
                remaining = top - len(signins)
                signins.extend(batch[:remaining])
                next_url = body.get("@odata.nextLink")
                next_params = None

            return {
                "success": True,
                "provider": self.provider,
                "details": "sign-in history listed",
                "signins": signins,
            }

        if action == "confirm_user_compromised":
            token = await get_graph_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}
            user_id = str(payload.get("user_id") or "").strip()
            if not user_id:
                raise ConnectorUnsupportedActionError("confirm_user_compromised requires payload.user_id")

            response = await self._request_with_retry(
                "POST",
                "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/confirmCompromised",
                headers=headers,
                json={"userIds": [user_id]},
            )
            confirmed = response.status_code == 204
            return {
                "success": confirmed,
                "provider": self.provider,
                "details": "user marked compromised" if confirmed else "unexpected status",
                "confirmed": confirmed,
                "user_id": user_id,
            }

        if action == "dismiss_risky_user":
            token = await get_graph_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}
            user_id = str(payload.get("user_id") or "").strip()
            if not user_id:
                raise ConnectorUnsupportedActionError("dismiss_risky_user requires payload.user_id")

            response = await self._request_with_retry(
                "POST",
                "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/dismiss",
                headers=headers,
                json={"userIds": [user_id]},
            )
            dismissed = response.status_code == 204
            return {
                "success": dismissed,
                "provider": self.provider,
                "details": "risky user dismissed" if dismissed else "unexpected status",
                "dismissed": dismissed,
                "user_id": user_id,
            }

        if action == "run_antivirus_scan":
            token = await get_defender_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}

            device_id = str(payload.get("device_id") or "").strip()
            if not device_id:
                raise ConnectorUnsupportedActionError("run_antivirus_scan requires payload.device_id")

            scan_type = "Full" if str(payload.get("scan_type") or "Quick").lower() == "full" else "Quick"
            body = {
                "Comment": f"Secamo orchestrator {scan_type.lower()} antivirus scan",
                "ScanType": scan_type,
            }

            try:
                response = await self._request_with_retry(
                    "POST",
                    f"https://api.securitycenter.microsoft.com/api/machines/{quote(device_id)}/runAntiVirusScan",
                    headers=headers,
                    json=body,
                )
            except ConnectorPermanentError as exc:
                if self._connector_error_status(exc) == 404:
                    return {
                        "success": True,
                        "provider": self.provider,
                        "details": "device not found",
                        "submitted": False,
                        "found": False,
                        "device_id": device_id,
                        "scan_type": scan_type,
                    }
                raise

            return {
                "success": True,
                "provider": self.provider,
                "details": "scan action submitted",
                "submitted": response.status_code in {200, 201, 202, 204},
                "found": True,
                "device_id": device_id,
                "scan_type": scan_type,
                "response": response.json() if response.content else {},
            }

        if action == "list_noncompliant_devices":
            token = await get_graph_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}

            url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"
            params = {
                "$filter": "complianceState eq 'noncompliant'",
                "$select": "id,deviceName,userPrincipalName,operatingSystem,osVersion,complianceState,lastSyncDateTime,azureADDeviceId",
                "$top": "200",
            }

            devices: list[dict[str, Any]] = []
            next_url: str | None = url
            next_params: dict[str, str] | None = params
            while next_url:
                response = await self._request_with_retry("GET", next_url, headers=headers, params=next_params)
                body = response.json()
                devices.extend(body.get("value", []))
                next_url = body.get("@odata.nextLink")
                next_params = None

            return {
                "success": True,
                "provider": self.provider,
                "details": "noncompliant devices listed",
                "devices": devices,
            }

        if action == "create_subscription":
            token = await get_graph_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}

            resource = self._normalize_subscription_resource(str(payload.get("resource") or ""))
            notification_url = str(payload.get("notification_url") or "").strip()
            client_state = str(payload.get("client_state") or "").strip()
            if not resource or not notification_url or not client_state:
                raise ConnectorUnsupportedActionError(
                    "create_subscription requires payload.resource, payload.notification_url and payload.client_state"
                )

            requested_minutes = int(payload.get("expiration_minutes") or 60)
            expiration_minutes = self._clamp_subscription_minutes(
                requested_minutes=requested_minutes,
                resource=resource,
            )
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=expiration_minutes)
            body: dict[str, Any] = {
                "changeType": str(payload.get("change_type") or ",".join(payload.get("change_types") or ["created", "updated"])),
                "notificationUrl": notification_url,
                "resource": resource,
                "expirationDateTime": self._format_odata_datetime(expires_at),
                "clientState": client_state,
            }

            include_resource_data = bool(payload.get("include_resource_data", False))
            if include_resource_data:
                certificate = str(payload.get("encryption_certificate") or "").strip()
                certificate_id = str(payload.get("encryption_certificate_id") or "").strip()
                if certificate and certificate_id:
                    body["includeResourceData"] = True
                    body["encryptionCertificate"] = certificate
                    body["encryptionCertificateId"] = certificate_id
            lifecycle_url = str(payload.get("lifecycle_notification_url") or "").strip()
            if lifecycle_url:
                body["lifecycleNotificationUrl"] = lifecycle_url

            response = await self._request_with_retry(
                "POST",
                "https://graph.microsoft.com/v1.0/subscriptions",
                headers=headers,
                json=body,
            )
            result = response.json()
            result.setdefault("success", True)
            result.setdefault("provider", self.provider)
            result.setdefault("details", "subscription created")
            return result

        if action == "renew_subscription":
            token = await get_graph_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}

            subscription_id = str(payload.get("subscription_id") or "").strip()
            if not subscription_id:
                raise ConnectorUnsupportedActionError("renew_subscription requires payload.subscription_id")

            resource_hint = self._normalize_subscription_resource(str(payload.get("resource") or ""))
            if not resource_hint:
                subscription_response = await self._request_with_retry(
                    "GET",
                    f"https://graph.microsoft.com/v1.0/subscriptions/{quote(subscription_id)}",
                    headers=headers,
                )
                subscription_body = subscription_response.json()
                resource_hint = self._normalize_subscription_resource(str(subscription_body.get("resource") or ""))

            requested_minutes = int(payload.get("expiration_minutes") or 60)
            expiration_minutes = self._clamp_subscription_minutes(
                requested_minutes=requested_minutes,
                resource=resource_hint,
            )
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=expiration_minutes)
            response = await self._request_with_retry(
                "PATCH",
                f"https://graph.microsoft.com/v1.0/subscriptions/{quote(subscription_id)}",
                headers=headers,
                json={"expirationDateTime": self._format_odata_datetime(expires_at)},
            )
            result = response.json()
            result.setdefault("success", True)
            result.setdefault("provider", self.provider)
            result.setdefault("details", "subscription renewed")
            return result

        if action == "delete_subscription":
            token = await get_graph_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}
            subscription_id = str(payload.get("subscription_id") or "").strip()
            if not subscription_id:
                raise ConnectorUnsupportedActionError("delete_subscription requires payload.subscription_id")

            try:
                await self._request_with_retry(
                    "DELETE",
                    f"https://graph.microsoft.com/v1.0/subscriptions/{quote(subscription_id)}",
                    headers=headers,
                )
            except ConnectorPermanentError as exc:
                if self._connector_error_status(exc) == 404:
                    return {
                        "success": True,
                        "provider": self.provider,
                        "details": "subscription not found",
                        "deleted": False,
                        "subscription_id": subscription_id,
                    }
                raise
            return {
                "success": True,
                "provider": self.provider,
                "details": "subscription deleted",
                "deleted": True,
                "subscription_id": subscription_id,
            }

        if action == "list_subscriptions":
            token = await get_graph_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}
            response = await self._request_with_retry(
                "GET",
                "https://graph.microsoft.com/v1.0/subscriptions",
                headers=headers,
            )
            body = response.json()
            return {
                "success": True,
                "provider": self.provider,
                "details": "subscriptions listed",
                "subscriptions": body.get("value", []),
            }

        if action == "send_email":
            token = await get_graph_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

            sender = str(payload.get("sender") or "").strip()
            to = str(payload.get("to") or "").strip()
            subject = str(payload.get("subject") or "")
            body_content = str(payload.get("body") or "")
            content_type = str(payload.get("content_type") or "Text")

            if not sender or not to:
                raise ConnectorUnsupportedActionError("send_email requires payload.sender and payload.to")

            response = await self._request_with_retry(
                "POST",
                f"https://graph.microsoft.com/v1.0/users/{quote(sender)}/sendMail",
                headers=headers,
                json={
                    "message": {
                        "subject": subject,
                        "body": {"contentType": content_type, "content": body_content},
                        "toRecipients": [{"emailAddress": {"address": to}}],
                    },
                    "saveToSentItems": "false",
                },
            )
            sent = response.status_code in {200, 202}
            return {
                "success": sent,
                "provider": self.provider,
                "details": "email sent" if sent else "unexpected status",
                "sent": sent,
                "message_id": response.headers.get("x-ms-request-id"),
                "recipient": to,
            }

        if action == "enrich_alert":
            token = await get_graph_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}
            alert_id = payload["alert_id"]
            url = f"https://graph.microsoft.com/v1.0/security/alerts_v2/{quote(alert_id)}"
            response = await self._request_with_retry("GET", url, headers=headers)
            return response.json()

        if action == "get_user":
            token = await get_graph_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}
            email = str(payload.get("email") or "").strip()
            if not email:
                raise ConnectorUnsupportedActionError("get_user requires payload.email")

            url = f"https://graph.microsoft.com/v1.0/users/{quote(email)}?$select=id,displayName,mail,userPrincipalName,accountEnabled"
            try:
                response = await self._request_with_retry("GET", url, headers=headers)
            except ConnectorPermanentError as exc:
                if self._connector_error_status(exc) == 404:
                    return {"found": False, "email": email}
                raise

            body = response.json()
            return {
                "found": True,
                "user_id": str(body.get("id") or ""),
                "email": str(body.get("mail") or body.get("userPrincipalName") or email),
                "display_name": str(body.get("displayName") or ""),
                "account_enabled": bool(body.get("accountEnabled", False)),
            }

        if action == "create_user":
            token = await get_graph_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}
            user_data = payload.get("user_data") if isinstance(payload.get("user_data"), dict) else {}
            body = self._build_graph_create_user_body(user_data)
            user_email = str(body["userPrincipalName"])

            try:
                response = await self._request_with_retry(
                    "POST",
                    "https://graph.microsoft.com/v1.0/users",
                    headers=headers,
                    json=body,
                )
            except ConnectorPermanentError as exc:
                if self._connector_error_status(exc) == 409:
                    return await self.execute_action("get_user", {"email": user_email})
                raise

            created = response.json()
            return {
                "found": True,
                "user_id": str(created.get("id") or ""),
                "email": str(created.get("mail") or created.get("userPrincipalName") or user_email),
                "display_name": str(created.get("displayName") or body["displayName"]),
                "account_enabled": bool(created.get("accountEnabled", True)),
            }

        if action == "update_user":
            token = await get_graph_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}
            user_id = str(payload.get("user_id") or "").strip()
            updates = payload.get("updates") if isinstance(payload.get("updates"), dict) else {}
            if not user_id:
                raise ConnectorUnsupportedActionError("update_user requires payload.user_id")

            normalized_updates = self._normalize_graph_user_updates(updates)
            if not normalized_updates:
                return {"updated": False, "user_id": user_id, "skipped": True}

            try:
                await self._request_with_retry(
                    "PATCH",
                    f"https://graph.microsoft.com/v1.0/users/{quote(user_id)}",
                    headers=headers,
                    json=normalized_updates,
                )
            except ConnectorPermanentError as exc:
                if self._connector_error_status(exc) == 404:
                    return {"updated": False, "user_id": user_id}
                raise

            return {"updated": True, "user_id": user_id}

        if action == "delete_user":
            token = await get_graph_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}
            user_id = str(payload.get("user_id") or "").strip()
            if not user_id:
                raise ConnectorUnsupportedActionError("delete_user requires payload.user_id")

            try:
                await self._request_with_retry(
                    "DELETE",
                    f"https://graph.microsoft.com/v1.0/users/{quote(user_id)}",
                    headers=headers,
                )
            except ConnectorPermanentError as exc:
                if self._connector_error_status(exc) == 404:
                    return {"deleted": False, "user_id": user_id}
                raise

            return {"deleted": True, "user_id": user_id}

        if action == "revoke_sessions":
            token = await get_graph_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}
            user_id = str(payload.get("user_id") or "").strip()
            if not user_id:
                raise ConnectorUnsupportedActionError("revoke_sessions requires payload.user_id")

            await self._request_with_retry(
                "POST",
                f"https://graph.microsoft.com/v1.0/users/{quote(user_id)}/revokeSignInSessions",
                headers=headers,
            )
            return {"revoked": True, "user_id": user_id}

        if action == "assign_license":
            token = await get_graph_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}
            user_id = str(payload.get("user_id") or "").strip()
            sku_id = str(payload.get("sku_id") or "").strip()
            if not user_id or not sku_id:
                raise ConnectorUnsupportedActionError("assign_license requires payload.user_id and payload.sku_id")

            await self._request_with_retry(
                "POST",
                f"https://graph.microsoft.com/v1.0/users/{quote(user_id)}/assignLicense",
                headers=headers,
                json={"addLicenses": [{"skuId": sku_id}], "removeLicenses": []},
            )
            return {"assigned": True, "user_id": user_id, "sku_id": sku_id}

        if action == "reset_password":
            token = await get_graph_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}
            user_id = str(payload.get("user_id") or "").strip()
            temp_password = str(payload.get("temp_password") or self._generate_password())
            if not user_id:
                raise ConnectorUnsupportedActionError("reset_password requires payload.user_id")

            try:
                await self._request_with_retry(
                    "PATCH",
                    f"https://graph.microsoft.com/v1.0/users/{quote(user_id)}",
                    headers=headers,
                    json={
                        "passwordProfile": {
                            "forceChangePasswordNextSignIn": True,
                            "password": temp_password,
                        }
                    },
                )
            except ConnectorPermanentError as exc:
                if self._connector_error_status(exc) == 404:
                    return {"reset": False, "user_id": user_id}
                raise

            return {"reset": True, "user_id": user_id}

        if action == "get_device_context":
            token = await get_defender_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}
            device_id = str(payload.get("device_id") or "").strip()
            if not device_id:
                raise ConnectorUnsupportedActionError("get_device_context requires payload.device_id")

            url = f"https://api.securitycenter.microsoft.com/api/machines/{quote(device_id)}"
            try:
                response = await self._request_with_retry("GET", url, headers=headers)
            except ConnectorPermanentError as exc:
                if "status=404" in str(exc):
                    return {
                        "provider": self.provider,
                        "found": False,
                        "device_id": device_id,
                    }
                raise

            body = response.json()
            return {
                "provider": self.provider,
                "found": True,
                "device_id": str(body.get("id") or device_id),
                "display_name": body.get("computerDnsName"),
                "os_platform": body.get("osPlatform"),
                "compliance_state": body.get("healthStatus"),
                "risk_score": body.get("riskScore"),
            }

        if action == "get_identity_risk":
            token = await get_graph_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}
            lookup_key = str(payload.get("lookup_key") or "").strip()
            if not lookup_key:
                raise ConnectorUnsupportedActionError("get_identity_risk requires payload.lookup_key")

            if "@" in lookup_key:
                escaped_lookup = self._escape_odata_literal(lookup_key)
                url = "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers"
                response = await self._request_with_retry(
                    "GET",
                    url,
                    headers=headers,
                    params={"$filter": f"userPrincipalName eq '{escaped_lookup}'", "$top": "1"},
                )
                body = response.json()
                item = (body.get("value") or [None])[0]
                if item is None:
                    return {
                        "provider": self.provider,
                        "found": False,
                        "subject": lookup_key,
                    }
            else:
                url = f"https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/{quote(lookup_key)}"
                try:
                    response = await self._request_with_retry("GET", url, headers=headers)
                except ConnectorPermanentError as exc:
                    if "status=404" in str(exc):
                        return {
                            "provider": self.provider,
                            "found": False,
                            "subject": lookup_key,
                        }
                    raise
                item = response.json()

            return {
                "provider": self.provider,
                "found": True,
                "subject": item.get("userPrincipalName") or lookup_key,
                "risk_level": item.get("riskLevel"),
                "risk_state": item.get("riskState"),
                "risk_detail": item.get("riskDetail"),
            }

        if action == "isolate_device":
            # TODO: validate tenant API permissions for Defender isolate endpoint.
            token = await get_defender_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}
            device_id = payload["device_id"]
            comment = payload.get("comment", "Isolated by Secamo workflow")
            body = {"Comment": comment, "IsolationType": "Full"}
            url = f"https://api.securitycenter.microsoft.com/api/machines/{quote(device_id)}/isolate"
            try:
                response = await self._request_with_retry("POST", url, headers=headers, json=body)
            except ConnectorPermanentError as exc:
                if self._connector_error_status(exc) == 404:
                    return {
                        "success": True,
                        "provider": self.provider,
                        "details": "device not found",
                        "submitted": False,
                        "found": False,
                        "device_id": device_id,
                    }
                raise
            if response.content:
                result = response.json()
                result.setdefault("submitted", True)
                result.setdefault("found", True)
            else:
                result = {"submitted": True, "found": True, "device_id": device_id}
            result.setdefault("success", True)
            result.setdefault("provider", self.provider)
            result.setdefault("details", "device isolation submitted")
            return result

        if action == "unisolate_device":
            token = await get_defender_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}
            device_id = str(payload.get("device_id") or "").strip()
            if not device_id:
                raise ConnectorUnsupportedActionError("unisolate_device requires payload.device_id")

            comment = str(payload.get("comment") or "Released from isolation by Secamo workflow")
            body = {"Comment": comment}
            url = f"https://api.securitycenter.microsoft.com/api/machines/{quote(device_id)}/unisolate"
            try:
                response = await self._request_with_retry("POST", url, headers=headers, json=body)
            except ConnectorPermanentError as exc:
                if self._connector_error_status(exc) == 404:
                    return {
                        "success": True,
                        "provider": self.provider,
                        "details": "device not found",
                        "submitted": False,
                        "found": False,
                        "device_id": device_id,
                    }
                raise

            if response.content:
                result = response.json()
                result.setdefault("submitted", True)
                result.setdefault("found", True)
            else:
                result = {"submitted": True, "found": True, "device_id": device_id}
            result.setdefault("success", True)
            result.setdefault("provider", self.provider)
            result.setdefault("details", "device unisolation submitted")
            return result

        raise ConnectorUnsupportedActionError(
            f"Unsupported action '{action}' for provider '{self.provider}'"
        )

    async def health_check(self) -> dict:
        token = await get_graph_token(self.secrets)
        headers = {"Authorization": f"Bearer {token}"}
        url = "https://graph.microsoft.com/v1.0/organization?$top=1"
        response = await self._request_with_retry("GET", url, headers=headers, timeout=15.0)
        ok = response.status_code == 200
        return {
            "healthy": ok,
            "status_code": response.status_code,
            "provider": self.provider,
        }


# Backwards-compatible alias for older imports.
MicrosoftDefenderConnector = MicrosoftGraphConnector
