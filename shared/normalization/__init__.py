"""Normalization package marker.

Normalization is now performed directly at ingress by building strict Envelope payloads.
"""

from shared.normalization.case_intake_defender import normalize_defender_alert_case
from shared.normalization.case_intake_impossible_travel import normalize_impossible_travel_case

__all__ = [
    "normalize_defender_alert_case",
    "normalize_impossible_travel_case",
]
