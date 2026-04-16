"""Normalization package marker.

Normalization is now performed directly at ingress by building strict Envelope payloads.
"""

from shared.normalization.soc import (
    normalize_audit_log_case,
    normalize_defender_alert_case,
    normalize_impossible_travel_case,
    normalize_noncompliant_device_case,
    normalize_risky_user_case,
    normalize_signin_log_case,
)

__all__ = [
    "normalize_audit_log_case",
    "normalize_defender_alert_case",
    "normalize_impossible_travel_case",
    "normalize_noncompliant_device_case",
    "normalize_risky_user_case",
    "normalize_signin_log_case",
]
