from __future__ import annotations

from pathlib import Path


def test_incident_response_requires_device_id_for_isolate() -> None:
    source = Path("workflows/child/incident_response.py").read_text(encoding="utf-8")

    assert "incident-response-require-device-id-v1" in source
    assert "IncidentResponse isolate action requires device_id" in source


def test_impossible_travel_propagates_device_id_to_child_requests() -> None:
    source = Path("workflows/impossible_travel.py").read_text(encoding="utf-8")

    assert "device_extension = payload.vendor_extensions.get(\"device_id\")" in source
    assert "device_id=device_id" in source
