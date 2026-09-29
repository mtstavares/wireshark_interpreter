from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class EnrichmentKind(StrEnum):
    TECHNIQUE = "technique"
    WEAKNESS = "weakness"
    VULNERABILITY = "vulnerability"
    PLATFORM = "platform"
    REPUTATION = "reputation"


@dataclass(frozen=True, slots=True)
class Enrichment:
    id: str
    analysis_id: str
    finding_id: str | None
    subject_type: str
    subject_value: str
    kind: EnrichmentKind
    namespace: str
    value: str
    title: str
    description: str
    confidence: float
    provider: str
    source_url: str | None
    retrieved_at: datetime
    expires_at: datetime | None
    cache_hit: bool = False
    influence: str = "context_only"


@dataclass(frozen=True, slots=True)
class AssetContext:
    analysis_id: str
    ip: str
    scope: str
    allowlisted: bool
    name: str | None = None
    role: str | None = None
    owner: str | None = None
    criticality: str | None = None
    labels: list[str] = field(default_factory=list[str])
    provenance: str = "automatic-ip-classification"
