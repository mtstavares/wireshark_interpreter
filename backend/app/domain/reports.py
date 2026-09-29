from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from backend.app.domain.analyses import AnalysisStatus, AnalyzerStatus
from backend.app.domain.enrichment import AssetContext, Enrichment
from backend.app.domain.findings import AssertionStatus, FindingEvidence, Severity
from backend.app.domain.network import HostInventory, ServiceInventory


@dataclass(frozen=True, slots=True)
class ReportCapture:
    id: str
    original_filename: str
    sha256: str
    size_bytes: int
    capture_format: str


@dataclass(frozen=True, slots=True)
class ReportAnalyzer:
    name: str
    status: AnalyzerStatus
    version: str | None
    diagnostic: str | None


@dataclass(frozen=True, slots=True)
class ReportSummary:
    flow_count: int
    event_count: int
    host_count: int
    service_count: int
    finding_count: int
    enrichment_count: int
    severity_counts: dict[Severity, int]
    first_seen: datetime | None
    last_seen: datetime | None


@dataclass(frozen=True, slots=True)
class ReportFinding:
    id: str
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
    wireshark_filter: str | None


@dataclass(frozen=True, slots=True)
class ReportActivity:
    occurred_at: datetime | None
    finding_id: str
    severity: Severity
    assertion_status: AssertionStatus
    statement: str
    source_ip: str | None
    destination_ip: str | None
    destination_port: int | None
    confidence: float
    evidence_refs: list[str]


@dataclass(frozen=True, slots=True)
class ReportTimelineEntry:
    occurred_at: datetime | None
    finding_id: str
    severity: Severity
    title: str


@dataclass(frozen=True, slots=True)
class ReportIndicator:
    type: str
    value: str
    finding_ids: list[str]


@dataclass(frozen=True, slots=True)
class SecurityReport:
    schema_version: str
    report_id: str
    generated_at: datetime
    analysis_id: str
    analysis_status: AnalysisStatus
    capture: ReportCapture
    executive_summary: str
    summary: ReportSummary
    analyzers: list[ReportAnalyzer]
    activities: list[ReportActivity]
    findings: list[ReportFinding]
    hosts: list[HostInventory]
    services: list[ServiceInventory]
    timeline: list[ReportTimelineEntry]
    indicators: list[ReportIndicator]
    enrichments: list[Enrichment]
    assets: list[AssetContext]
    limitations: list[str] = field(default_factory=list[str])
