"""Normalization package marker.

Normalization is now performed directly at ingress by building strict Envelope payloads.
"""

from shared.normalization.soc import normalize_defender_alert_case, normalize_impossible_travel_case

__all__ = [
    "normalize_defender_alert_case",
    "normalize_impossible_travel_case",
]
