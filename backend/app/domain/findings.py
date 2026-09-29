from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from backend.app.domain.network import NetworkEvent, NetworkFlow


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AssertionStatus(StrEnum):
    OBSERVED = "observed"
    INFERRED = "inferred"
    SIGNATURE_MATCH = "signature_match"
    POTENTIAL = "potential"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"


class DetectionStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class FindingEvidence:
    kind: str
    reference: str
    source: str


@dataclass(frozen=True, slots=True)
class Finding:
    id: str
    analysis_id: str
    title: str
    category: str
    severity: Severity
    confidence: float
    assertion_status: AssertionStatus
    summary: str
    first_seen: datetime | None
    last_seen: datetime | None
    source_ip: str | None
    destination_ip: str | None
    destination_port: int | None
    evidence: list[FindingEvidence]
    mitigations: list[str]
    mitre_attack: list[str]
    detector_name: str
    detector_version: str


@dataclass(frozen=True, slots=True)
class DetectionSummary:
    status: DetectionStatus
    finding_count: int = 0
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None


@dataclass(frozen=True, slots=True)
class DetectionContext:
    analysis_id: str
    flows: list[NetworkFlow] = field(default_factory=list[NetworkFlow])
    events: list[NetworkEvent] = field(default_factory=list[NetworkEvent])
