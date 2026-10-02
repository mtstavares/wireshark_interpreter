from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from backend.app.analyzers.command import Analyzer
from backend.app.application.detect_findings import DetectionService
from backend.app.application.enrich_analysis import EnrichmentService
from backend.app.application.normalize_analysis import NormalizationService
from backend.app.domain.analyses import Analysis, AnalysisStatus, AnalyzerStatus
from backend.app.infrastructure.database import AnalysisRepository, CaptureRepository


class AnalysisNotFoundError(Exception):
    pass


class CaptureNotFoundError(Exception):
    pass


class AnalysisStateError(Exception):
    pass


class AnalysisService:
    def __init__(
        self,
        capture_repository: CaptureRepository,
        analysis_repository: AnalysisRepository,
        analyzers: list[Analyzer],
        captures_dir: Path,
        analyses_dir: Path,
        timeout_seconds: int,
        normalization_service: NormalizationService,
        detection_service: DetectionService,
        enrichment_service: EnrichmentService,
    ) -> None:
        self._capture_repository = capture_repository
        self._analysis_repository = analysis_repository
        self._analyzers = analyzers
        self._captures_dir = captures_dir
        self._analyses_dir = analyses_dir
        self._timeout_seconds = timeout_seconds
        self._normalization_service = normalization_service
        self._detection_service = detection_service
        self._enrichment_service = enrichment_service

    def create(self, capture_id: str) -> Analysis:
        if self._capture_repository.get(capture_id) is None:
            raise CaptureNotFoundError(capture_id)
        analysis = Analysis(
            id=str(uuid4()),
            capture_id=capture_id,
            status=AnalysisStatus.QUEUED,
            created_at=datetime.now(UTC),
        )
        return self._analysis_repository.create(
            analysis, [analyzer.name for analyzer in self._analyzers]
        )

    def get(self, analysis_id: str) -> Analysis:
        analysis = self._analysis_repository.get(analysis_id)
        if analysis is None:
            raise AnalysisNotFoundError(analysis_id)
        return analysis

    def list_for_capture(self, capture_id: str, limit: int = 50) -> list[Analysis]:
        if self._capture_repository.get(capture_id) is None:
            raise CaptureNotFoundError(capture_id)
        return self._analysis_repository.list_for_capture(capture_id, limit)

    def run(self, analysis_id: str) -> None:
        analysis = self.get(analysis_id)
        if analysis.status is AnalysisStatus.CANCELED:
            return
        capture = self._capture_repository.get(analysis.capture_id)
        if capture is None:
            self._analysis_repository.update_status(
                analysis_id,
                AnalysisStatus.FAILED,
                completed_at=datetime.now(UTC),
                error_message="Capture metadata no longer exists",
            )
            return

        capture_path = self._captures_dir / capture.stored_filename
        if not capture_path.is_file():
            self._analysis_repository.update_status(
                analysis_id,
                AnalysisStatus.FAILED,
                completed_at=datetime.now(UTC),
                error_message="Capture file no longer exists",
            )
            return

        self._analysis_repository.update_status(
            analysis_id, AnalysisStatus.RUNNING, started_at=datetime.now(UTC)
        )
        completed_count = 0
        failure_count = 0

        for analyzer in self._analyzers:
            if self.get(analysis_id).status is AnalysisStatus.CANCELED:
                return
            self._analysis_repository.update_run(
                analysis_id, analyzer.name, status=AnalyzerStatus.RUNNING
            )
            if self.get(analysis_id).status is AnalysisStatus.CANCELED:
                return
            output_dir = self._analyses_dir / analysis_id / analyzer.name
            try:
                result = analyzer.analyze(capture_path, output_dir, self._timeout_seconds)
            except Exception as exc:
                result_status = AnalyzerStatus.FAILED
                self._analysis_repository.update_run(
                    analysis_id,
                    analyzer.name,
                    status=result_status,
                    diagnostic=f"Unexpected analyzer error: {type(exc).__name__}: {exc}",
                )
                failure_count += 1
                continue

            self._analysis_repository.update_run(
                analysis_id,
                analyzer.name,
                status=result.status,
                version=result.version,
                duration_ms=result.duration_ms,
                exit_code=result.exit_code,
                diagnostic=result.diagnostic,
                artifacts=result.artifacts,
            )
            if result.status is AnalyzerStatus.COMPLETED:
                completed_count += 1
            else:
                failure_count += 1

        if completed_count == len(self._analyzers):
            final_status = AnalysisStatus.COMPLETED
        elif completed_count > 0:
            final_status = AnalysisStatus.COMPLETED_WITH_WARNINGS
        else:
            final_status = AnalysisStatus.FAILED

        normalization_completed = False
        try:
            self._normalization_service.normalize(analysis_id)
            normalization_completed = True
        except Exception:
            failure_count += 1
            if completed_count > 0:
                final_status = AnalysisStatus.COMPLETED_WITH_WARNINGS
            else:
                final_status = AnalysisStatus.FAILED

        detection_completed = False
        if normalization_completed:
            try:
                self._detection_service.detect(analysis_id)
                detection_completed = True
            except Exception:
                failure_count += 1
                if completed_count > 0:
                    final_status = AnalysisStatus.COMPLETED_WITH_WARNINGS
                else:
                    final_status = AnalysisStatus.FAILED

        if detection_completed:
            try:
                self._enrichment_service.enrich(analysis_id)
            except Exception:
                failure_count += 1
                final_status = AnalysisStatus.COMPLETED_WITH_WARNINGS

        self._analysis_repository.update_status(
            analysis_id,
            final_status,
            completed_at=datetime.now(UTC),
            error_message=(
                f"{failure_count} pipeline component(s) did not complete successfully"
                if failure_count
                else None
            ),
        )

    def cancel(self, analysis_id: str) -> Analysis:
        analysis = self.get(analysis_id)
        if analysis.status not in {AnalysisStatus.QUEUED, AnalysisStatus.RUNNING}:
            raise AnalysisStateError("Only queued or running analyses can be canceled")
        self._analysis_repository.cancel(analysis_id, datetime.now(UTC))
        for analyzer in self._analyzers:
            cancel = getattr(analyzer, "cancel", None)
            if callable(cancel):
                cancel(analysis_id)
        return self.get(analysis_id)
