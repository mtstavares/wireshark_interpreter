from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from backend.app.domain.analyses import Analysis, AnalysisStatus, AnalyzerStatus
from backend.app.domain.captures import Capture, CaptureFormat, CaptureStatus
from backend.app.domain.enrichment import EnrichmentKind
from backend.app.domain.findings import AssertionStatus, DetectionStatus, Finding, Severity
from backend.app.domain.network import NormalizationStatus
from backend.app.domain.reports import SecurityReport


class CaptureResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    original_filename: str
    sha256: str
    size_bytes: int
    capture_format: CaptureFormat
    status: CaptureStatus
    created_at: datetime

    @classmethod
    def from_domain(cls, capture: Capture) -> "CaptureResponse":
        return cls.model_validate(capture)


class ProblemDetail(BaseModel):
    type: str = "about:blank"
    title: str
    status: int
    detail: str


class ArtifactResponse(BaseModel):
    path: str
    size_bytes: int


class AnalyzerRunResponse(BaseModel):
    id: str
    analyzer: str
    status: AnalyzerStatus
    version: str | None
    duration_ms: int | None
    exit_code: int | None
    diagnostic: str | None
    artifacts: list[ArtifactResponse]


class NormalizationResponse(BaseModel):
    status: NormalizationStatus
    flow_count: int
    event_count: int
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None


class DetectionResponse(BaseModel):
    status: DetectionStatus
    finding_count: int
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None


class AnalysisResponse(BaseModel):
    id: str
    capture_id: str
    status: AnalysisStatus
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    analyzer_runs: list[AnalyzerRunResponse]
    normalization: NormalizationResponse | None
    detection: DetectionResponse | None

    @classmethod
    def from_domain(cls, analysis: Analysis) -> "AnalysisResponse":
        return cls.model_validate(analysis, from_attributes=True)


class NetworkFlowResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    analysis_id: str
    sources: list[str]
    external_ids: list[str]
    start_time: datetime
    end_time: datetime
    src_ip: str
    src_port: int | None
    dest_ip: str
    dest_port: int | None
    transport: str
    application: str | None
    src_bytes: int
    dest_bytes: int
    src_packets: int
    dest_packets: int
    evidence_refs: list[str]


class NetworkEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    analysis_id: str
    source: str
    event_type: str
    occurred_at: datetime | None
    src_ip: str | None
    src_port: int | None
    dest_ip: str | None
    dest_port: int | None
    transport: str | None
    application: str | None
    external_flow_id: str | None
    evidence_ref: str
    details: dict[str, Any]


class HostInventoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ip: str
    first_seen: datetime
    last_seen: datetime
    sent_bytes: int
    received_bytes: int
    transports: list[str]
    applications: list[str]


class ServiceInventoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ip: str
    port: int
    transport: str
    application: str | None
    flow_count: int


class NetworkInventoryResponse(BaseModel):
    hosts: list[HostInventoryResponse]
    services: list[ServiceInventoryResponse]


class FindingEvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    kind: str
    reference: str
    source: str


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

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
    evidence: list[FindingEvidenceResponse]
    mitigations: list[str]
    mitre_attack: list[str]
    detector_name: str
    detector_version: str

    @classmethod
    def from_domain(cls, finding: Finding) -> "FindingResponse":
        return cls.model_validate(finding)


class EnrichmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

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
    cache_hit: bool
    influence: str


class AssetContextResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    analysis_id: str
    ip: str
    scope: str
    allowlisted: bool
    name: str | None
    role: str | None
    owner: str | None
    criticality: str | None
    labels: list[str]
    provenance: str


class ReportCaptureResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    original_filename: str
    sha256: str
    size_bytes: int
    capture_format: str


class ReportAnalyzerResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    status: AnalyzerStatus
    version: str | None
    diagnostic: str | None


class ReportSummaryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    flow_count: int
    event_count: int
    host_count: int
    service_count: int
    finding_count: int
    enrichment_count: int
    severity_counts: dict[Severity, int]
    first_seen: datetime | None
    last_seen: datetime | None


class ReportFindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

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
    evidence: list[FindingEvidenceResponse]
    mitigations: list[str]
    mitre_attack: list[str]
    detector_name: str
    detector_version: str
    wireshark_filter: str | None


class ReportTimelineResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    occurred_at: datetime | None
    finding_id: str
    severity: Severity
    title: str


class ReportActivityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

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


class ReportIndicatorResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    type: str
    value: str
    finding_ids: list[str]


class SecurityReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    schema_version: str
    report_id: str
    generated_at: datetime
    analysis_id: str
    analysis_status: AnalysisStatus
    capture: ReportCaptureResponse
    executive_summary: str
    summary: ReportSummaryResponse
    analyzers: list[ReportAnalyzerResponse]
    activities: list[ReportActivityResponse]
    findings: list[ReportFindingResponse]
    hosts: list[HostInventoryResponse]
    services: list[ServiceInventoryResponse]
    timeline: list[ReportTimelineResponse]
    indicators: list[ReportIndicatorResponse]
    enrichments: list[EnrichmentResponse]
    assets: list[AssetContextResponse]
    limitations: list[str]

    @classmethod
    def from_domain(cls, report: SecurityReport) -> "SecurityReportResponse":
        return cls.model_validate(report)
