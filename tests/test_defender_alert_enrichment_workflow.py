from __future__ import annotations

from workflows.defender_alert_enrichment import DefenderAlertEnrichmentWorkflow


def test_extract_ips_from_evidence_prefers_ip_evidence() -> None:
    payload = {
        "evidence": [
            {
                "@odata.type": "#microsoft.graph.security.ipEvidence",
                "ipAddress": "8.8.8.8",
            },
            {
                "@odata.type": "#microsoft.graph.security.networkConnectionEvidence",
                "sourceAddress": "1.2.3.4",
                "destinationAddress": "5.6.7.8",
            },
        ]
    }

    source_ip, destination_ip = DefenderAlertEnrichmentWorkflow._extract_ips_from_evidence(payload)

    assert source_ip == "8.8.8.8"
    assert destination_ip == "5.6.7.8"


def test_extract_ips_from_evidence_uses_network_connection_when_needed() -> None:
    payload = {
        "evidence": [
            {
                "@odata.type": "#microsoft.graph.security.networkConnectionEvidence",
                "sourceAddress": "1.2.3.4",
                "destinationAddress": "5.6.7.8",
            }
        ]
    }

    source_ip, destination_ip = DefenderAlertEnrichmentWorkflow._extract_ips_from_evidence(payload)

    assert source_ip == "1.2.3.4"
    assert destination_ip == "5.6.7.8"


def test_extract_ips_from_evidence_handles_missing_or_invalid_values() -> None:
    payload = {
        "evidence": [
            {
                "@odata.type": "#microsoft.graph.security.ipEvidence",
                "ipAddress": "not-an-ip",
            },
            {
                "@odata.type": "#microsoft.graph.security.networkConnectionEvidence",
                "sourceAddress": "",
                "destinationAddress": "bad-ip",
            },
        ]
    }

    source_ip, destination_ip = DefenderAlertEnrichmentWorkflow._extract_ips_from_evidence(payload)

    assert source_ip is None
    assert destination_ip is None
