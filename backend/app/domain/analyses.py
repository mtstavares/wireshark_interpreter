from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from backend.app.domain.findings import DetectionSummary
from backend.app.domain.network import NormalizationSummary


class AnalysisStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_WARNINGS = "completed_with_warnings"
    FAILED = "failed"


class AnalyzerStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    TIMED_OUT = "timed_out"


@dataclass(frozen=True, slots=True)
class Artifact:
    path: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class AnalyzerRun:
    id: str
    analyzer: str
    status: AnalyzerStatus
    version: str | None = None
    duration_ms: int | None = None
    exit_code: int | None = None
    diagnostic: str | None = None
    artifacts: list[Artifact] = field(default_factory=list[Artifact])


@dataclass(frozen=True, slots=True)
class Analysis:
    id: str
    capture_id: str
    status: AnalysisStatus
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None
    analyzer_runs: list[AnalyzerRun] = field(default_factory=list[AnalyzerRun])
    normalization: NormalizationSummary | None = None
    detection: DetectionSummary | None = None
