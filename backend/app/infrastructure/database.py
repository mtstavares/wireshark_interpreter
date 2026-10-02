from __future__ import annotations

import json
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from alembic import command
from alembic.config import Config
from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    delete,
    insert,
    select,
    update,
)
from sqlalchemy.engine import URL, Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from backend.app.domain.analyses import (
    Analysis,
    AnalysisStatus,
    AnalyzerRun,
    AnalyzerStatus,
    Artifact,
)
from backend.app.domain.captures import Capture, CaptureFormat, CaptureStatus
from backend.app.domain.enrichment import Enrichment, EnrichmentKind
from backend.app.domain.findings import (
    AssertionStatus,
    DetectionStatus,
    DetectionSummary,
    Finding,
    FindingEvidence,
    Severity,
)
from backend.app.domain.network import (
    HostInventory,
    NetworkEvent,
    NetworkFlow,
    NetworkInventory,
    NormalizationStatus,
    NormalizationSummary,
    ServiceInventory,
)
from backend.app.domain.validation import (
    AnalystConclusion,
    Validation,
    ValidationAuditEntry,
    ValidationStatus,
    ValidationTechnicalResult,
)


class Base(DeclarativeBase):
    pass


class CaptureRecord(Base):
    __tablename__ = "captures"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    stored_filename: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    capture_format: Mapped[str] = mapped_column(String(10), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AnalysisRecord(Base):
    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    capture_id: Mapped[str] = mapped_column(ForeignKey("captures.id"), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)


class AnalyzerRunRecord(Base):
    __tablename__ = "analyzer_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), index=True, nullable=False)
    analyzer: Mapped[str] = mapped_column(String(30), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    version: Mapped[str | None] = mapped_column(String(300))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    exit_code: Mapped[int | None] = mapped_column(Integer)
    diagnostic: Mapped[str | None] = mapped_column(Text)
    artifacts_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")


class NormalizationRecord(Base):
    __tablename__ = "normalizations"

    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id"), primary_key=True, nullable=False
    )
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    flow_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)


class NetworkFlowRecord(Base):
    __tablename__ = "network_flows"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), index=True, nullable=False)
    sources_json: Mapped[str] = mapped_column(Text, nullable=False)
    external_ids_json: Mapped[str] = mapped_column(Text, nullable=False)
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    src_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    src_port: Mapped[int | None] = mapped_column(Integer)
    dest_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    dest_port: Mapped[int | None] = mapped_column(Integer)
    transport: Mapped[str] = mapped_column(String(20), nullable=False)
    application: Mapped[str | None] = mapped_column(String(80))
    src_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    dest_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    src_packets: Mapped[int] = mapped_column(Integer, nullable=False)
    dest_packets: Mapped[int] = mapped_column(Integer, nullable=False)
    evidence_refs_json: Mapped[str] = mapped_column(Text, nullable=False)


class NetworkEventRecord(Base):
    __tablename__ = "network_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(30), nullable=False)
    event_type: Mapped[str] = mapped_column(String(80), index=True, nullable=False)
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    src_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    src_port: Mapped[int | None] = mapped_column(Integer)
    dest_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    dest_port: Mapped[int | None] = mapped_column(Integer)
    transport: Mapped[str | None] = mapped_column(String(20))
    application: Mapped[str | None] = mapped_column(String(80))
    external_flow_id: Mapped[str | None] = mapped_column(String(120))
    evidence_ref: Mapped[str] = mapped_column(String(300), nullable=False)
    details_json: Mapped[str] = mapped_column(Text, nullable=False)


class DetectionRecord(Base):
    __tablename__ = "detections"

    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id"), primary_key=True, nullable=False
    )
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)


class FindingRecord(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    category: Mapped[str] = mapped_column(String(80), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), index=True, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    assertion_status: Mapped[str] = mapped_column(String(30), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    destination_port: Mapped[int | None] = mapped_column(Integer)
    evidence_json: Mapped[str] = mapped_column(Text, nullable=False)
    mitigations_json: Mapped[str] = mapped_column(Text, nullable=False)
    mitre_attack_json: Mapped[str] = mapped_column(Text, nullable=False)
    detector_name: Mapped[str] = mapped_column(String(80), nullable=False)
    detector_version: Mapped[str] = mapped_column(String(40), nullable=False)


class EnrichmentRecord(Base):
    __tablename__ = "enrichments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), index=True, nullable=False)
    finding_id: Mapped[str | None] = mapped_column(String(36), index=True)
    subject_type: Mapped[str] = mapped_column(String(30), nullable=False)
    subject_value: Mapped[str] = mapped_column(String(300), index=True, nullable=False)
    kind: Mapped[str] = mapped_column(String(30), index=True, nullable=False)
    namespace: Mapped[str] = mapped_column(String(30), nullable=False)
    value: Mapped[str] = mapped_column(String(300), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    provider: Mapped[str] = mapped_column(String(120), index=True, nullable=False)
    source_url: Mapped[str | None] = mapped_column(Text)
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cache_hit: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    influence: Mapped[str] = mapped_column(String(30), nullable=False)


class ValidationRecord(Base):
    __tablename__ = "validations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), index=True, nullable=False)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True, nullable=False)
    validator: Mapped[str] = mapped_column(String(50), nullable=False)
    target_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    target_port: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(30), index=True, nullable=False)
    policy_allowed: Mapped[int] = mapped_column(Integer, nullable=False)
    policy_reason: Mapped[str] = mapped_column(Text, nullable=False)
    scope_reference: Mapped[str] = mapped_column(String(300), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(120), nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    technical_result: Mapped[str] = mapped_column(String(30), nullable=False)
    analyst_conclusion: Mapped[str] = mapped_column(String(30), nullable=False)
    result_summary: Mapped[str | None] = mapped_column(Text)
    review_rationale: Mapped[str | None] = mapped_column(Text)
    reviewed_by: Mapped[str | None] = mapped_column(String(120))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ValidationAuditRecord(Base):
    __tablename__ = "validation_audit"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    validation_id: Mapped[str] = mapped_column(
        ForeignKey("validations.id"), index=True, nullable=False
    )
    action: Mapped[str] = mapped_column(String(60), nullable=False)
    actor: Mapped[str] = mapped_column(String(120), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    details_json: Mapped[str] = mapped_column(Text, nullable=False)


def create_database_engine(database_path: Path) -> Engine:
    url = URL.create("sqlite+pysqlite", database=str(database_path))
    engine = create_engine(
        url,
        connect_args={"check_same_thread": False, "timeout": 30},
    )
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA journal_mode=WAL")
        connection.exec_driver_sql("PRAGMA synchronous=NORMAL")
    return engine


def initialize_database(engine: Engine) -> None:
    migrations_dir = Path(__file__).resolve().parents[1] / "migrations"
    config = Config()
    config.set_main_option("script_location", str(migrations_dir))
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")


class CaptureRepository:
    def __init__(self, engine: Engine) -> None:
        self._session_factory = sessionmaker(engine, expire_on_commit=False)

    def add(self, capture: Capture) -> Capture:
        record = CaptureRecord(
            id=capture.id,
            original_filename=capture.original_filename,
            stored_filename=capture.stored_filename,
            sha256=capture.sha256,
            size_bytes=capture.size_bytes,
            capture_format=capture.capture_format.value,
            status=capture.status.value,
            created_at=capture.created_at,
        )
        with self._session_factory.begin() as session:
            session.add(record)
        return capture

    def get(self, capture_id: str) -> Capture | None:
        with self._session_factory() as session:
            record = session.get(CaptureRecord, capture_id)
            return None if record is None else _to_domain(record)

    def list(self, limit: int = 50) -> list[Capture]:
        statement = select(CaptureRecord).order_by(CaptureRecord.created_at.desc()).limit(limit)
        with self._session_factory() as session:
            records = session.scalars(statement).all()
            return [_to_domain(record) for record in records]


def _to_domain(record: CaptureRecord) -> Capture:
    created_at = record.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)
    return Capture(
        id=record.id,
        original_filename=record.original_filename,
        stored_filename=record.stored_filename,
        sha256=record.sha256,
        size_bytes=record.size_bytes,
        capture_format=CaptureFormat(record.capture_format),
        status=CaptureStatus(record.status),
        created_at=created_at,
    )


class AnalysisRepository:
    def __init__(self, engine: Engine) -> None:
        self._session_factory = sessionmaker(engine, expire_on_commit=False)

    def create(self, analysis: Analysis, analyzer_names: list[str]) -> Analysis:
        with self._session_factory.begin() as session:
            session.add(
                AnalysisRecord(
                    id=analysis.id,
                    capture_id=analysis.capture_id,
                    status=analysis.status.value,
                    created_at=analysis.created_at,
                    started_at=analysis.started_at,
                    completed_at=analysis.completed_at,
                    error_message=analysis.error_message,
                )
            )
            session.add_all(
                AnalyzerRunRecord(
                    id=f"{analysis.id}:{name}",
                    analysis_id=analysis.id,
                    analyzer=name,
                    status=AnalyzerStatus.PENDING.value,
                    artifacts_json="[]",
                )
                for name in analyzer_names
            )
            session.add(
                NormalizationRecord(
                    analysis_id=analysis.id,
                    status=NormalizationStatus.PENDING.value,
                    flow_count=0,
                    event_count=0,
                )
            )
            session.add(
                DetectionRecord(
                    analysis_id=analysis.id,
                    status=DetectionStatus.PENDING.value,
                    finding_count=0,
                )
            )
        created = self.get(analysis.id)
        if created is None:
            raise RuntimeError("Analysis was not persisted")
        return created

    def get(self, analysis_id: str) -> Analysis | None:
        with self._session_factory() as session:
            record = session.get(AnalysisRecord, analysis_id)
            if record is None:
                return None
            runs = session.scalars(
                select(AnalyzerRunRecord)
                .where(AnalyzerRunRecord.analysis_id == analysis_id)
                .order_by(AnalyzerRunRecord.analyzer)
            ).all()
            normalization = session.get(NormalizationRecord, analysis_id)
            detection = session.get(DetectionRecord, analysis_id)
            return _analysis_to_domain(record, runs, normalization, detection)

    def list_for_capture(self, capture_id: str, limit: int = 50) -> list[Analysis]:
        statement = (
            select(AnalysisRecord)
            .where(AnalysisRecord.capture_id == capture_id)
            .order_by(AnalysisRecord.created_at.desc())
            .limit(limit)
        )
        with self._session_factory() as session:
            records = session.scalars(statement).all()
        return [analysis for record in records if (analysis := self.get(record.id)) is not None]

    def update_status(
        self,
        analysis_id: str,
        status: AnalysisStatus,
        *,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
        error_message: str | None = None,
    ) -> None:
        with self._session_factory.begin() as session:
            record = session.get(AnalysisRecord, analysis_id)
            if record is None:
                raise KeyError(analysis_id)
            record.status = status.value
            if started_at is not None:
                record.started_at = started_at
            if completed_at is not None:
                record.completed_at = completed_at
            record.error_message = error_message

    def recover_interrupted(self, recovered_at: datetime) -> int:
        interrupted = (AnalysisStatus.QUEUED.value, AnalysisStatus.RUNNING.value)
        diagnostic = "Analysis interrupted by an application restart"
        with self._session_factory.begin() as session:
            analysis_ids = list(
                session.scalars(
                    select(AnalysisRecord.id).where(AnalysisRecord.status.in_(interrupted))
                )
            )
            if not analysis_ids:
                return 0
            session.execute(
                update(AnalysisRecord)
                .where(AnalysisRecord.id.in_(analysis_ids))
                .values(
                    status=AnalysisStatus.FAILED.value,
                    completed_at=recovered_at,
                    error_message=diagnostic,
                )
            )
            session.execute(
                update(AnalyzerRunRecord)
                .where(
                    AnalyzerRunRecord.analysis_id.in_(analysis_ids),
                    AnalyzerRunRecord.status == AnalyzerStatus.RUNNING.value,
                )
                .values(status=AnalyzerStatus.FAILED.value, diagnostic=diagnostic)
            )
            session.execute(
                update(NormalizationRecord)
                .where(
                    NormalizationRecord.analysis_id.in_(analysis_ids),
                    NormalizationRecord.status == NormalizationStatus.RUNNING.value,
                )
                .values(
                    status=NormalizationStatus.FAILED.value,
                    completed_at=recovered_at,
                    error_message=diagnostic,
                )
            )
            session.execute(
                update(DetectionRecord)
                .where(
                    DetectionRecord.analysis_id.in_(analysis_ids),
                    DetectionRecord.status == DetectionStatus.RUNNING.value,
                )
                .values(
                    status=DetectionStatus.FAILED.value,
                    completed_at=recovered_at,
                    error_message=diagnostic,
                )
            )
        return len(analysis_ids)

    def cancel(self, analysis_id: str, canceled_at: datetime) -> None:
        diagnostic = "Analysis canceled by user"
        with self._session_factory.begin() as session:
            record = session.get(AnalysisRecord, analysis_id)
            if record is None:
                raise KeyError(analysis_id)
            record.status = AnalysisStatus.CANCELED.value
            record.completed_at = canceled_at
            record.error_message = diagnostic
            session.execute(
                update(AnalyzerRunRecord)
                .where(
                    AnalyzerRunRecord.analysis_id == analysis_id,
                    AnalyzerRunRecord.status.in_(
                        [AnalyzerStatus.PENDING.value, AnalyzerStatus.RUNNING.value]
                    ),
                )
                .values(status=AnalyzerStatus.CANCELED.value, diagnostic=diagnostic)
            )

    def update_run(
        self,
        analysis_id: str,
        analyzer: str,
        *,
        status: AnalyzerStatus,
        version: str | None = None,
        duration_ms: int | None = None,
        exit_code: int | None = None,
        diagnostic: str | None = None,
        artifacts: list[Artifact] | None = None,
    ) -> None:
        run_id = f"{analysis_id}:{analyzer}"
        with self._session_factory.begin() as session:
            record = session.get(AnalyzerRunRecord, run_id)
            if record is None:
                raise KeyError(run_id)
            record.status = status.value
            record.version = version
            record.duration_ms = duration_ms
            record.exit_code = exit_code
            record.diagnostic = diagnostic
            if artifacts is not None:
                record.artifacts_json = json.dumps(
                    [{"path": item.path, "size_bytes": item.size_bytes} for item in artifacts]
                )


def _analysis_to_domain(
    record: AnalysisRecord,
    runs: Sequence[AnalyzerRunRecord],
    normalization: NormalizationRecord | None,
    detection: DetectionRecord | None,
) -> Analysis:
    return Analysis(
        id=record.id,
        capture_id=record.capture_id,
        status=AnalysisStatus(record.status),
        created_at=_required_utc(record.created_at),
        started_at=_as_utc(record.started_at),
        completed_at=_as_utc(record.completed_at),
        error_message=record.error_message,
        analyzer_runs=[
            AnalyzerRun(
                id=run.id,
                analyzer=run.analyzer,
                status=AnalyzerStatus(run.status),
                version=run.version,
                duration_ms=run.duration_ms,
                exit_code=run.exit_code,
                diagnostic=run.diagnostic,
                artifacts=[Artifact(**item) for item in json.loads(run.artifacts_json)],
            )
            for run in runs
        ],
        normalization=(
            NormalizationSummary(
                status=NormalizationStatus(normalization.status),
                flow_count=normalization.flow_count,
                event_count=normalization.event_count,
                started_at=_as_utc(normalization.started_at),
                completed_at=_as_utc(normalization.completed_at),
                error_message=normalization.error_message,
            )
            if normalization is not None
            else None
        ),
        detection=(
            DetectionSummary(
                status=DetectionStatus(detection.status),
                finding_count=detection.finding_count,
                started_at=_as_utc(detection.started_at),
                completed_at=_as_utc(detection.completed_at),
                error_message=detection.error_message,
            )
            if detection is not None
            else None
        ),
    )


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _required_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


@dataclass(slots=True)
class _HostAccumulator:
    first_seen: datetime
    last_seen: datetime
    sent_bytes: int = 0
    received_bytes: int = 0
    transports: set[str] = field(default_factory=set[str])
    applications: set[str] = field(default_factory=set[str])


class NetworkRepository:
    _WRITE_BATCH_SIZE = 2_000

    def __init__(self, engine: Engine) -> None:
        self._session_factory = sessionmaker(engine, expire_on_commit=False)

    def start_normalization(self, analysis_id: str, started_at: datetime) -> None:
        with self._session_factory.begin() as session:
            record = session.get(NormalizationRecord, analysis_id)
            if record is None:
                raise KeyError(analysis_id)
            record.status = NormalizationStatus.RUNNING.value
            record.started_at = started_at
            record.completed_at = None
            record.error_message = None

    def save_results(
        self,
        analysis_id: str,
        flows: list[NetworkFlow],
        events: list[NetworkEvent],
        completed_at: datetime,
    ) -> None:
        with self._session_factory.begin() as session:
            session.execute(
                delete(NetworkFlowRecord).where(NetworkFlowRecord.analysis_id == analysis_id)
            )
            session.execute(
                delete(NetworkEventRecord).where(NetworkEventRecord.analysis_id == analysis_id)
            )
            for batch in _batched((_flow_values(flow) for flow in flows), self._WRITE_BATCH_SIZE):
                session.execute(insert(NetworkFlowRecord), batch)
            for batch in _batched(
                (_event_values(event) for event in events), self._WRITE_BATCH_SIZE
            ):
                session.execute(insert(NetworkEventRecord), batch)
            normalization = session.get(NormalizationRecord, analysis_id)
            if normalization is None:
                raise KeyError(analysis_id)
            normalization.status = NormalizationStatus.COMPLETED.value
            normalization.flow_count = len(flows)
            normalization.event_count = len(events)
            normalization.completed_at = completed_at
            normalization.error_message = None

    def fail_normalization(self, analysis_id: str, completed_at: datetime, error: str) -> None:
        with self._session_factory.begin() as session:
            normalization = session.get(NormalizationRecord, analysis_id)
            if normalization is None:
                raise KeyError(analysis_id)
            normalization.status = NormalizationStatus.FAILED.value
            normalization.completed_at = completed_at
            normalization.error_message = error[:2000]

    def list_flows(self, analysis_id: str, limit: int = 100) -> list[NetworkFlow]:
        statement = (
            select(NetworkFlowRecord)
            .where(NetworkFlowRecord.analysis_id == analysis_id)
            .order_by(NetworkFlowRecord.start_time)
            .limit(limit)
        )
        with self._session_factory() as session:
            records = session.scalars(statement).all()
            return [_flow_to_domain(record) for record in records]

    def list_events(self, analysis_id: str, limit: int = 100) -> list[NetworkEvent]:
        statement = (
            select(NetworkEventRecord)
            .where(NetworkEventRecord.analysis_id == analysis_id)
            .order_by(NetworkEventRecord.occurred_at)
            .limit(limit)
        )
        with self._session_factory() as session:
            records = session.scalars(statement).all()
            return [_event_to_domain(record) for record in records]

    def inventory(self, analysis_id: str) -> NetworkInventory:
        flows = self.list_flows(analysis_id, limit=100_000)
        hosts: dict[str, _HostAccumulator] = {}
        services: dict[tuple[str, int, str, str | None], int] = {}
        for flow in flows:
            _update_host(hosts, flow.src_ip, flow, sent=flow.src_bytes, received=flow.dest_bytes)
            _update_host(hosts, flow.dest_ip, flow, sent=flow.dest_bytes, received=flow.src_bytes)
            if flow.dest_port is not None:
                key = (flow.dest_ip, flow.dest_port, flow.transport, flow.application)
                services[key] = services.get(key, 0) + 1
        return NetworkInventory(
            hosts=[
                HostInventory(
                    ip=ip,
                    first_seen=values.first_seen,
                    last_seen=values.last_seen,
                    sent_bytes=values.sent_bytes,
                    received_bytes=values.received_bytes,
                    transports=sorted(values.transports),
                    applications=sorted(values.applications),
                )
                for ip, values in sorted(hosts.items())
            ],
            services=[
                ServiceInventory(
                    ip=key[0],
                    port=key[1],
                    transport=key[2],
                    application=key[3],
                    flow_count=count,
                )
                for key, count in sorted(
                    services.items(),
                    key=lambda item: (
                        item[0][0],
                        item[0][1],
                        item[0][2],
                        item[0][3] or "",
                    ),
                )
            ],
        )


def _flow_values(flow: NetworkFlow) -> dict[str, object]:
    return {
        "id": flow.id,
        "analysis_id": flow.analysis_id,
        "sources_json": json.dumps(flow.sources),
        "external_ids_json": json.dumps(flow.external_ids),
        "start_time": flow.start_time,
        "end_time": flow.end_time,
        "src_ip": flow.src_ip,
        "src_port": flow.src_port,
        "dest_ip": flow.dest_ip,
        "dest_port": flow.dest_port,
        "transport": flow.transport,
        "application": flow.application,
        "src_bytes": flow.src_bytes,
        "dest_bytes": flow.dest_bytes,
        "src_packets": flow.src_packets,
        "dest_packets": flow.dest_packets,
        "evidence_refs_json": json.dumps(flow.evidence_refs),
    }


def _event_values(event: NetworkEvent) -> dict[str, object]:
    return {
        "id": event.id,
        "analysis_id": event.analysis_id,
        "source": event.source,
        "event_type": event.event_type,
        "occurred_at": event.occurred_at,
        "src_ip": event.src_ip,
        "src_port": event.src_port,
        "dest_ip": event.dest_ip,
        "dest_port": event.dest_port,
        "transport": event.transport,
        "application": event.application,
        "external_flow_id": event.external_flow_id,
        "evidence_ref": event.evidence_ref,
        "details_json": json.dumps(event.details, ensure_ascii=False),
    }


def _batched(
    values: Iterator[dict[str, object]], batch_size: int
) -> Iterator[list[dict[str, object]]]:
    batch: list[dict[str, object]] = []
    for value in values:
        batch.append(value)
        if len(batch) == batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


def _flow_to_domain(record: NetworkFlowRecord) -> NetworkFlow:
    return NetworkFlow(
        id=record.id,
        analysis_id=record.analysis_id,
        sources=json.loads(record.sources_json),
        external_ids=json.loads(record.external_ids_json),
        start_time=_required_utc(record.start_time),
        end_time=_required_utc(record.end_time),
        src_ip=record.src_ip,
        src_port=record.src_port,
        dest_ip=record.dest_ip,
        dest_port=record.dest_port,
        transport=record.transport,
        application=record.application,
        src_bytes=record.src_bytes,
        dest_bytes=record.dest_bytes,
        src_packets=record.src_packets,
        dest_packets=record.dest_packets,
        evidence_refs=json.loads(record.evidence_refs_json),
    )


def _event_to_domain(record: NetworkEventRecord) -> NetworkEvent:
    return NetworkEvent(
        id=record.id,
        analysis_id=record.analysis_id,
        source=record.source,
        event_type=record.event_type,
        occurred_at=_as_utc(record.occurred_at),
        src_ip=record.src_ip,
        src_port=record.src_port,
        dest_ip=record.dest_ip,
        dest_port=record.dest_port,
        transport=record.transport,
        application=record.application,
        external_flow_id=record.external_flow_id,
        evidence_ref=record.evidence_ref,
        details=json.loads(record.details_json),
    )


def _update_host(
    hosts: dict[str, _HostAccumulator],
    ip: str,
    flow: NetworkFlow,
    *,
    sent: int,
    received: int,
) -> None:
    values = hosts.setdefault(ip, _HostAccumulator(flow.start_time, flow.end_time))
    values.first_seen = min(values.first_seen, flow.start_time)
    values.last_seen = max(values.last_seen, flow.end_time)
    values.sent_bytes += sent
    values.received_bytes += received
    values.transports.add(flow.transport)
    if flow.application:
        values.applications.add(flow.application)


class FindingRepository:
    def __init__(self, engine: Engine) -> None:
        self._session_factory = sessionmaker(engine, expire_on_commit=False)

    def start_detection(self, analysis_id: str, started_at: datetime) -> None:
        with self._session_factory.begin() as session:
            record = session.get(DetectionRecord, analysis_id)
            if record is None:
                raise KeyError(analysis_id)
            record.status = DetectionStatus.RUNNING.value
            record.started_at = started_at
            record.completed_at = None
            record.error_message = None

    def save_findings(
        self,
        analysis_id: str,
        findings: list[Finding],
        completed_at: datetime,
    ) -> None:
        with self._session_factory.begin() as session:
            session.execute(delete(FindingRecord).where(FindingRecord.analysis_id == analysis_id))
            session.add_all(_finding_record(finding) for finding in findings)
            detection = session.get(DetectionRecord, analysis_id)
            if detection is None:
                raise KeyError(analysis_id)
            detection.status = DetectionStatus.COMPLETED.value
            detection.finding_count = len(findings)
            detection.completed_at = completed_at
            detection.error_message = None

    def fail_detection(self, analysis_id: str, completed_at: datetime, error: str) -> None:
        with self._session_factory.begin() as session:
            detection = session.get(DetectionRecord, analysis_id)
            if detection is None:
                raise KeyError(analysis_id)
            detection.status = DetectionStatus.FAILED.value
            detection.completed_at = completed_at
            detection.error_message = error[:2000]

    def get(self, finding_id: str) -> Finding | None:
        with self._session_factory() as session:
            record = session.get(FindingRecord, finding_id)
            return None if record is None else _finding_to_domain(record)

    def list(
        self,
        analysis_id: str,
        *,
        severity: Severity | None = None,
        category: str | None = None,
        limit: int = 100,
    ) -> list[Finding]:
        statement = select(FindingRecord).where(FindingRecord.analysis_id == analysis_id)
        if severity is not None:
            statement = statement.where(FindingRecord.severity == severity.value)
        if category is not None:
            statement = statement.where(FindingRecord.category == category)
        with self._session_factory() as session:
            records = session.scalars(statement.limit(limit)).all()
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFORMATIONAL: 4,
        }
        findings = [_finding_to_domain(record) for record in records]
        return sorted(findings, key=lambda item: (severity_order[item.severity], -item.confidence))


def _finding_record(finding: Finding) -> FindingRecord:
    return FindingRecord(
        id=finding.id,
        analysis_id=finding.analysis_id,
        title=finding.title,
        category=finding.category,
        severity=finding.severity.value,
        confidence=finding.confidence,
        assertion_status=finding.assertion_status.value,
        summary=finding.summary,
        first_seen=finding.first_seen,
        last_seen=finding.last_seen,
        source_ip=finding.source_ip,
        destination_ip=finding.destination_ip,
        destination_port=finding.destination_port,
        evidence_json=json.dumps(
            [
                {"kind": item.kind, "reference": item.reference, "source": item.source}
                for item in finding.evidence
            ]
        ),
        mitigations_json=json.dumps(finding.mitigations, ensure_ascii=False),
        mitre_attack_json=json.dumps(finding.mitre_attack),
        detector_name=finding.detector_name,
        detector_version=finding.detector_version,
    )


def _finding_to_domain(record: FindingRecord) -> Finding:
    evidence_data = json.loads(record.evidence_json)
    mitigation_data = json.loads(record.mitigations_json)
    mitre_data = json.loads(record.mitre_attack_json)
    return Finding(
        id=record.id,
        analysis_id=record.analysis_id,
        title=record.title,
        category=record.category,
        severity=Severity(record.severity),
        # Older development databases stored this column as VARCHAR.  SQLite
        # keeps that original affinity when create_all() is run again, so
        # normalize the value at the repository boundary for compatibility.
        confidence=float(record.confidence),
        assertion_status=AssertionStatus(record.assertion_status),
        summary=record.summary,
        first_seen=_as_utc(record.first_seen),
        last_seen=_as_utc(record.last_seen),
        source_ip=record.source_ip,
        destination_ip=record.destination_ip,
        destination_port=record.destination_port,
        evidence=[
            FindingEvidence(
                kind=str(item["kind"]),
                reference=str(item["reference"]),
                source=str(item["source"]),
            )
            for item in evidence_data
        ],
        mitigations=[str(item) for item in mitigation_data],
        mitre_attack=[str(item) for item in mitre_data],
        detector_name=record.detector_name,
        detector_version=record.detector_version,
    )


class EnrichmentRepository:
    def __init__(self, engine: Engine) -> None:
        self._session_factory = sessionmaker(engine, expire_on_commit=False)

    def replace(self, analysis_id: str, enrichments: list[Enrichment]) -> None:
        with self._session_factory.begin() as session:
            session.execute(
                delete(EnrichmentRecord).where(EnrichmentRecord.analysis_id == analysis_id)
            )
            session.add_all(_enrichment_record(item) for item in enrichments)

    def list(self, analysis_id: str, limit: int = 10_000) -> list[Enrichment]:
        statement = (
            select(EnrichmentRecord)
            .where(EnrichmentRecord.analysis_id == analysis_id)
            .order_by(EnrichmentRecord.kind, EnrichmentRecord.namespace, EnrichmentRecord.value)
            .limit(limit)
        )
        with self._session_factory() as session:
            records = session.scalars(statement).all()
        return [_enrichment_to_domain(record) for record in records]

    def find_cached(
        self,
        *,
        provider: str,
        subject_value: str,
        kind: EnrichmentKind,
        value: str,
        now: datetime,
        exclude_analysis_id: str,
    ) -> Enrichment | None:
        statement = (
            select(EnrichmentRecord)
            .where(
                EnrichmentRecord.provider == provider,
                EnrichmentRecord.subject_value == subject_value,
                EnrichmentRecord.kind == kind.value,
                EnrichmentRecord.value == value,
                EnrichmentRecord.analysis_id != exclude_analysis_id,
            )
            .order_by(EnrichmentRecord.retrieved_at.desc())
        )
        with self._session_factory() as session:
            records = session.scalars(statement).all()
        for record in records:
            item = _enrichment_to_domain(record)
            if item.expires_at is None or item.expires_at > now:
                return item
        return None


def _enrichment_record(item: Enrichment) -> EnrichmentRecord:
    return EnrichmentRecord(
        id=item.id,
        analysis_id=item.analysis_id,
        finding_id=item.finding_id,
        subject_type=item.subject_type,
        subject_value=item.subject_value,
        kind=item.kind.value,
        namespace=item.namespace,
        value=item.value,
        title=item.title,
        description=item.description,
        confidence=item.confidence,
        provider=item.provider,
        source_url=item.source_url,
        retrieved_at=item.retrieved_at,
        expires_at=item.expires_at,
        cache_hit=int(item.cache_hit),
        influence=item.influence,
    )


def _enrichment_to_domain(record: EnrichmentRecord) -> Enrichment:
    return Enrichment(
        id=record.id,
        analysis_id=record.analysis_id,
        finding_id=record.finding_id,
        subject_type=record.subject_type,
        subject_value=record.subject_value,
        kind=EnrichmentKind(record.kind),
        namespace=record.namespace,
        value=record.value,
        title=record.title,
        description=record.description,
        confidence=float(record.confidence),
        provider=record.provider,
        source_url=record.source_url,
        retrieved_at=_as_utc(record.retrieved_at) or record.retrieved_at,
        expires_at=_as_utc(record.expires_at),
        cache_hit=bool(record.cache_hit),
        influence=record.influence,
    )


class ValidationRepository:
    def __init__(self, engine: Engine) -> None:
        self._session_factory = sessionmaker(engine, expire_on_commit=False)

    def create(
        self,
        validation: Validation,
        *,
        action: str,
        actor: str,
        details: dict[str, str | int | bool | None],
    ) -> Validation:
        with self._session_factory.begin() as session:
            session.add(_validation_record(validation))
            _add_validation_audit(
                session,
                validation.id,
                action,
                actor,
                validation.created_at,
                details,
            )
        created = self.get(validation.id)
        if created is None:
            raise RuntimeError("Validation was not persisted")
        return created

    def get(self, validation_id: str) -> Validation | None:
        with self._session_factory() as session:
            record = session.get(ValidationRecord, validation_id)
            if record is None:
                return None
            audits = session.scalars(
                select(ValidationAuditRecord)
                .where(ValidationAuditRecord.validation_id == validation_id)
                .order_by(ValidationAuditRecord.occurred_at, ValidationAuditRecord.id)
            ).all()
            return _validation_to_domain(record, audits)

    def list(self, analysis_id: str, limit: int = 1000) -> list[Validation]:
        with self._session_factory() as session:
            ids = session.scalars(
                select(ValidationRecord.id)
                .where(ValidationRecord.analysis_id == analysis_id)
                .order_by(ValidationRecord.created_at.desc())
                .limit(limit)
            ).all()
        return [item for validation_id in ids if (item := self.get(validation_id)) is not None]

    def approve(self, validation_id: str, actor: str, approved_at: datetime) -> Validation:
        with self._session_factory.begin() as session:
            record = _required_validation(session, validation_id)
            record.status = ValidationStatus.APPROVED.value
            record.approved_by = actor
            record.approved_at = approved_at
            _add_validation_audit(
                session,
                validation_id,
                "approved",
                actor,
                approved_at,
                {"approval_phrase_verified": True},
            )
        return self._required_result(validation_id)

    def block(self, validation_id: str, reason: str, occurred_at: datetime) -> Validation:
        with self._session_factory.begin() as session:
            record = _required_validation(session, validation_id)
            record.status = ValidationStatus.BLOCKED.value
            record.policy_allowed = 0
            record.policy_reason = reason
            record.completed_at = occurred_at
            _add_validation_audit(
                session,
                validation_id,
                "blocked",
                "policy-engine",
                occurred_at,
                {"reason": reason},
            )
        return self._required_result(validation_id)

    def start(self, validation_id: str, started_at: datetime) -> None:
        with self._session_factory.begin() as session:
            record = _required_validation(session, validation_id)
            record.status = ValidationStatus.RUNNING.value
            record.started_at = started_at
            _add_validation_audit(
                session,
                validation_id,
                "execution_started",
                "validation-runner",
                started_at,
                {"validator": record.validator},
            )

    def complete(
        self,
        validation_id: str,
        result: ValidationTechnicalResult,
        summary: str,
        completed_at: datetime,
        *,
        failed: bool = False,
    ) -> Validation:
        with self._session_factory.begin() as session:
            record = _required_validation(session, validation_id)
            record.status = (
                ValidationStatus.FAILED.value if failed else ValidationStatus.COMPLETED.value
            )
            record.technical_result = result.value
            record.result_summary = summary[:4000]
            record.completed_at = completed_at
            _add_validation_audit(
                session,
                validation_id,
                "execution_failed" if failed else "execution_completed",
                "validation-runner",
                completed_at,
                {"technical_result": result.value, "summary": summary[:1000]},
            )
        return self._required_result(validation_id)

    def review(
        self,
        validation_id: str,
        conclusion: AnalystConclusion,
        rationale: str,
        actor: str,
        reviewed_at: datetime,
    ) -> Validation:
        with self._session_factory.begin() as session:
            record = _required_validation(session, validation_id)
            record.analyst_conclusion = conclusion.value
            record.review_rationale = rationale[:4000]
            record.reviewed_by = actor
            record.reviewed_at = reviewed_at
            _add_validation_audit(
                session,
                validation_id,
                "analyst_reviewed",
                actor,
                reviewed_at,
                {"conclusion": conclusion.value, "rationale": rationale[:1000]},
            )
        return self._required_result(validation_id)

    def recover_interrupted(self, recovered_at: datetime) -> int:
        statuses = (ValidationStatus.APPROVED.value, ValidationStatus.RUNNING.value)
        with self._session_factory.begin() as session:
            records = session.scalars(
                select(ValidationRecord).where(ValidationRecord.status.in_(statuses))
            ).all()
            for record in records:
                record.status = ValidationStatus.FAILED.value
                record.technical_result = ValidationTechnicalResult.ERROR.value
                record.result_summary = "Validation interrupted by an application restart"
                record.completed_at = recovered_at
                _add_validation_audit(
                    session,
                    record.id,
                    "interrupted",
                    "application",
                    recovered_at,
                    {"reason": "application_restart"},
                )
        return len(records)

    def _required_result(self, validation_id: str) -> Validation:
        validation = self.get(validation_id)
        if validation is None:
            raise KeyError(validation_id)
        return validation


def _validation_record(item: Validation) -> ValidationRecord:
    return ValidationRecord(
        id=item.id,
        analysis_id=item.analysis_id,
        finding_id=item.finding_id,
        validator=item.validator,
        target_ip=item.target_ip,
        target_port=item.target_port,
        status=item.status.value,
        policy_allowed=int(item.policy_allowed),
        policy_reason=item.policy_reason,
        scope_reference=item.scope_reference,
        requested_by=item.requested_by,
        approved_by=item.approved_by,
        created_at=item.created_at,
        approved_at=item.approved_at,
        started_at=item.started_at,
        completed_at=item.completed_at,
        technical_result=item.technical_result.value,
        analyst_conclusion=item.analyst_conclusion.value,
        result_summary=item.result_summary,
        review_rationale=item.review_rationale,
        reviewed_by=item.reviewed_by,
        reviewed_at=item.reviewed_at,
    )


def _validation_to_domain(
    record: ValidationRecord, audits: Sequence[ValidationAuditRecord]
) -> Validation:
    return Validation(
        id=record.id,
        analysis_id=record.analysis_id,
        finding_id=record.finding_id,
        validator=record.validator,
        target_ip=record.target_ip,
        target_port=record.target_port,
        status=ValidationStatus(record.status),
        policy_allowed=bool(record.policy_allowed),
        policy_reason=record.policy_reason,
        scope_reference=record.scope_reference,
        requested_by=record.requested_by,
        approved_by=record.approved_by,
        created_at=_required_utc(record.created_at),
        approved_at=_as_utc(record.approved_at),
        started_at=_as_utc(record.started_at),
        completed_at=_as_utc(record.completed_at),
        technical_result=ValidationTechnicalResult(record.technical_result),
        analyst_conclusion=AnalystConclusion(record.analyst_conclusion),
        result_summary=record.result_summary,
        review_rationale=record.review_rationale,
        reviewed_by=record.reviewed_by,
        reviewed_at=_as_utc(record.reviewed_at),
        audit=[
            ValidationAuditEntry(
                id=audit.id,
                validation_id=audit.validation_id,
                action=audit.action,
                actor=audit.actor,
                occurred_at=_required_utc(audit.occurred_at),
                details={
                    str(key): value
                    for key, value in json.loads(audit.details_json).items()
                    if isinstance(value, (str, int, bool)) or value is None
                },
            )
            for audit in audits
        ],
    )


def _required_validation(session: Session, validation_id: str) -> ValidationRecord:
    record = session.get(ValidationRecord, validation_id)
    if record is None:
        raise KeyError(validation_id)
    return record


def _add_validation_audit(
    session: Session,
    validation_id: str,
    action: str,
    actor: str,
    occurred_at: datetime,
    details: dict[str, str | int | bool | None],
) -> None:
    session.add(
        ValidationAuditRecord(
            id=str(uuid4()),
            validation_id=validation_id,
            action=action,
            actor=actor,
            occurred_at=occurred_at,
            details_json=json.dumps(details, ensure_ascii=False, sort_keys=True),
        )
    )
