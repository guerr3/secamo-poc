from __future__ import annotations

from temporalio.exceptions import ApplicationError


_RETRYABLE_HTTP_STATUSES = {
    408,
    409,
    429,
    500,
    502,
    503,
    504,
    507,
    509,
}


def is_retryable_http_status(status_code: int) -> bool:
    """Return True when the HTTP status is typically transient/retryable."""
    if status_code in _RETRYABLE_HTTP_STATUSES:
        return True
    if status_code >= 500:
        return True
    return False


def application_error_from_http_status(
    tenant_id: str,
    provider: str,
    action: str,
    status_code: int,
    *,
    error_type_prefix: str = "ExternalApiError",
    retry_after_seconds: int | None = None,
) -> ApplicationError:
    """Build a Temporal ApplicationError with explicit retryability from HTTP status."""
    retryable = is_retryable_http_status(status_code)
    retry_after_suffix = (
        f" retry_after={retry_after_seconds}s" if retry_after_seconds is not None else ""
    )
    message = (
        f"[{tenant_id}] {provider} {action} failed "
        f"status={status_code}{retry_after_suffix}"
    )
    return ApplicationError(
        message,
        type=f"{error_type_prefix}{status_code}",
        non_retryable=not retryable,
    )


def raise_activity_error(
    message: str,
    *,
    error_type: str,
    non_retryable: bool,
) -> None:
    """Raise a typed ApplicationError for non-HTTP activity failures."""
    raise ApplicationError(
        message,
        type=error_type,
        non_retryable=non_retryable,
    )
