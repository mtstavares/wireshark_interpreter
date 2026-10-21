from __future__ import annotations

from typing import Any


def quality_baseline() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "capture": "comprehensive-attacks.pcap",
        "capture_sha256": "fafad737ba42e53faf3ed15c15d08f808430c7383687741ab99bdbd369c15099",
        "detector_version": "1.2.0",
        "validated_on": "2026-10-21",
        "true_positive": 23,
        "false_positive": 0,
        "false_negative": 0,
        "precision": 1.0,
        "recall": 1.0,
        "detectors": [
            _metric("authentication-abuse", 2),
            _metric("beaconing", 1),
            _metric("cleartext-credential", 9),
            _metric("cleartext-protocol", 4),
            _metric("dns-anomaly", 1),
            _metric("port-scan", 2),
            _metric("web-attack-payload", 4),
        ],
        "limitations": [
            "As métricas descrevem somente o corpus sintético versionado.",
            "SSH não expõe credenciais ou resultado de autenticação no PCAP.",
            "HTTP 2xx isolado não confirma exploração; conteúdo e logs devem ser correlacionados.",
            "Regras e tráfego diferentes podem produzir métricas distintas.",
        ],
    }


def _metric(detector: str, true_positive: int) -> dict[str, str | int | float]:
    return {
        "detector": detector,
        "true_positive": true_positive,
        "false_positive": 0,
        "false_negative": 0,
        "precision": 1.0,
        "recall": 1.0,
    }
