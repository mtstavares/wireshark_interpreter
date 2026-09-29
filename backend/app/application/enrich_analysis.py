from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, cast
from uuid import NAMESPACE_URL, uuid5

from backend.app.domain.enrichment import AssetContext, Enrichment, EnrichmentKind
from backend.app.domain.findings import Finding
from backend.app.infrastructure.database import (
    EnrichmentRepository,
    FindingRepository,
    NetworkRepository,
)

_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_BUILTIN_REFERENCES: dict[str, list[dict[str, object]]] = {
    "cleartext-protocol": [
        {
            "kind": "weakness",
            "namespace": "CWE",
            "value": "CWE-319",
            "title": "Cleartext Transmission of Sensitive Information",
            "description": "O protocolo observado não oferece proteção criptográfica adequada.",
            "confidence": 0.95,
            "source_url": "https://cwe.mitre.org/data/definitions/319.html",
        }
    ],
    "legacy-snmp": [
        {
            "kind": "weakness",
            "namespace": "CWE",
            "value": "CWE-319",
            "title": "Cleartext Transmission of Sensitive Information",
            "description": (
                "SNMPv1/v2c não protege o conteúdo e as community strings com criptografia."
            ),
            "confidence": 0.99,
            "source_url": "https://cwe.mitre.org/data/definitions/319.html",
        }
    ],
    "authentication-abuse": [
        {
            "kind": "weakness",
            "namespace": "CWE",
            "value": "CWE-307",
            "title": "Improper Restriction of Excessive Authentication Attempts",
            "description": (
                "Múltiplas tentativas podem indicar ausência ou insuficiência de limitação."
            ),
            "confidence": 0.75,
            "source_url": "https://cwe.mitre.org/data/definitions/307.html",
        }
    ],
}


class EnrichmentService:
    def __init__(
        self,
        network_repository: NetworkRepository,
        finding_repository: FindingRepository,
        enrichment_repository: EnrichmentRepository,
        *,
        asset_context_path: Path | None = None,
        reputation_path: Path | None = None,
        catalog_path: Path | None = None,
    ) -> None:
        self._network_repository = network_repository
        self._finding_repository = finding_repository
        self._enrichment_repository = enrichment_repository
        self._asset_context_path = asset_context_path
        self._reputation_path = reputation_path
        self._catalog_path = catalog_path

    def enrich(self, analysis_id: str) -> list[Enrichment]:
        now = datetime.now(UTC)
        findings = self._finding_repository.list(analysis_id, limit=1_000_000)
        inventory = self._network_repository.inventory(analysis_id)
        catalog = _merge_catalog(_BUILTIN_REFERENCES, _load_json(self._catalog_path))
        enrichments = [
            item
            for finding in findings
            for item in _finding_enrichments(analysis_id, finding, catalog, now)
        ]
        reputation = _load_json(self._reputation_path)
        for host in inventory.hosts:
            enrichments.extend(self._reputation_enrichments(analysis_id, host.ip, reputation, now))
        self._enrichment_repository.replace(analysis_id, enrichments)
        return enrichments

    def list(self, analysis_id: str) -> list[Enrichment]:
        return self._enrichment_repository.list(analysis_id)

    def assets(self, analysis_id: str) -> list[AssetContext]:
        config = _load_json(self._asset_context_path)
        allowlist = _string_list(config.get("allowlist"))
        assets = _mapping(config.get("assets"))
        return [
            _asset_context(analysis_id, host.ip, allowlist, assets)
            for host in self._network_repository.inventory(analysis_id).hosts
        ]

    def _reputation_enrichments(
        self,
        analysis_id: str,
        ip: str,
        data: Mapping[str, object],
        now: datetime,
    ) -> list[Enrichment]:
        indicators = _mapping(data.get("indicators"))
        raw = _mapping(indicators.get(ip))
        if not raw:
            return []
        verdict = str(raw.get("verdict", "unknown")).lower()
        provider = str(data.get("provider", "local-reputation-file"))
        expires_at = _datetime(raw.get("expires_at"))
        cached = self._enrichment_repository.find_cached(
            provider=provider,
            subject_value=ip,
            kind=EnrichmentKind.REPUTATION,
            value=verdict,
            now=now,
            exclude_analysis_id=analysis_id,
        )
        retrieved_at = cached.retrieved_at if cached else now
        return [
            Enrichment(
                id=_id(analysis_id, ip, provider, verdict),
                analysis_id=analysis_id,
                finding_id=None,
                subject_type="ip",
                subject_value=ip,
                kind=EnrichmentKind.REPUTATION,
                namespace="reputation",
                value=verdict,
                title=f"Reputação local: {verdict}",
                description=str(raw.get("description", "Indicador fornecido pelo catálogo local.")),
                confidence=_confidence(raw.get("confidence", 0.5)),
                provider=provider,
                source_url=_optional_url(raw.get("source_url")),
                retrieved_at=retrieved_at,
                expires_at=expires_at,
                cache_hit=cached is not None,
            )
        ]


def _finding_enrichments(
    analysis_id: str,
    finding: Finding,
    catalog: Mapping[str, object],
    now: datetime,
) -> list[Enrichment]:
    entries: list[Mapping[str, object]] = []
    raw_entries = catalog.get(finding.detector_name, [])
    if isinstance(raw_entries, list):
        for item in cast(list[object], raw_entries):
            if isinstance(item, Mapping):
                entries.append(cast(Mapping[str, object], item))
    entries.extend(
        {
            "kind": "technique",
            "namespace": "MITRE ATT&CK",
            "value": technique,
            "title": f"MITRE ATT&CK {technique}",
            "description": "Técnica associada pelo detector determinístico.",
            "confidence": finding.confidence,
            "source_url": f"https://attack.mitre.org/techniques/{technique.replace('.', '/')}/",
        }
        for technique in finding.mitre_attack
    )
    for cve in sorted(set(_CVE_PATTERN.findall(f"{finding.title} {finding.summary}"))):
        canonical = cve.upper()
        entries.append(
            {
                "kind": "vulnerability",
                "namespace": "CVE",
                "value": canonical,
                "title": canonical,
                "description": (
                    "CVE citado pela assinatura ou descrição do finding; não confirmado."
                ),
                "confidence": min(finding.confidence, 0.8),
                "source_url": f"https://www.cve.org/CVERecord?id={canonical}",
            }
        )
    result: list[Enrichment] = []
    seen: set[tuple[str, str]] = set()
    for entry in entries:
        namespace = str(entry.get("namespace", "custom"))
        value = str(entry.get("value", "")).strip()
        if not value or (namespace, value) in seen:
            continue
        seen.add((namespace, value))
        try:
            kind = EnrichmentKind(str(entry.get("kind", "weakness")))
        except ValueError:
            continue
        result.append(
            Enrichment(
                id=_id(analysis_id, finding.id, namespace, value),
                analysis_id=analysis_id,
                finding_id=finding.id,
                subject_type="finding",
                subject_value=finding.id,
                kind=kind,
                namespace=namespace,
                value=value,
                title=str(entry.get("title", value)),
                description=str(entry.get("description", "Contexto adicional.")),
                confidence=_confidence(entry.get("confidence", finding.confidence)),
                provider=str(entry.get("provider", "builtin-knowledge")),
                source_url=_optional_url(entry.get("source_url")),
                retrieved_at=now,
                expires_at=None,
            )
        )
    return result


def _asset_context(
    analysis_id: str,
    ip: str,
    allowlist: list[str],
    configured: Mapping[str, object],
) -> AssetContext:
    address = ip_address(ip)
    entry = configured.get(ip)
    values = _mapping(entry)
    allowlisted = any(address in ip_network(item, strict=False) for item in allowlist)
    return AssetContext(
        analysis_id=analysis_id,
        ip=ip,
        scope=_ip_scope(address),
        allowlisted=allowlisted,
        name=_optional_text(values.get("name")),
        role=_optional_text(values.get("role")),
        owner=_optional_text(values.get("owner")),
        criticality=_optional_text(values.get("criticality")),
        labels=_string_list(values.get("labels")),
        provenance="asset-context-file" if values or allowlisted else "automatic-ip-classification",
    )


def _ip_scope(address: Any) -> str:
    if address.is_multicast:
        return "multicast"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if address.is_private:
        return "private"
    if address.is_reserved:
        return "reserved"
    return "public"


def _load_json(path: Path | None) -> Mapping[str, object]:
    if path is None:
        return {}
    raw = cast(object, json.loads(path.read_text(encoding="utf-8")))
    if not isinstance(raw, Mapping):
        raise ValueError(f"Expected a JSON object in {path}")
    return cast(Mapping[str, object], raw)


def _merge_catalog(
    builtin: Mapping[str, list[dict[str, object]]], custom: Mapping[str, object]
) -> dict[str, object]:
    merged: dict[str, object] = {key: list(value) for key, value in builtin.items()}
    for key, value in custom.items():
        if isinstance(value, list):
            current = merged.setdefault(key, [])
            if isinstance(current, list):
                target = cast(list[object], current)
                for item in cast(list[object], value):
                    if isinstance(item, Mapping):
                        custom_entry = dict(cast(Mapping[str, object], item))
                        custom_entry["provider"] = "custom-catalog"
                        target.append(custom_entry)
    return merged


def _datetime(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.astimezone(UTC)


def _confidence(value: object) -> float:
    try:
        numeric = float(cast(Any, value))
    except (TypeError, ValueError):
        numeric = 0.5
    return round(max(0.0, min(numeric, 1.0)), 3)


def _optional_text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _optional_url(value: object) -> str | None:
    text = _optional_text(value)
    return text if text and text.lower().startswith(("https://", "http://")) else None


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        return {}
    return cast(Mapping[str, object], value)


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in cast(list[object], value) if str(item).strip()]


def _id(*parts: str) -> str:
    return str(uuid5(NAMESPACE_URL, "enrichment:" + ":".join(parts)))
