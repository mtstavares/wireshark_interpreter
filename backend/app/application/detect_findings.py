from __future__ import annotations

from datetime import UTC, datetime

from backend.app.detection.detectors import Detector
from backend.app.domain.findings import DetectionContext
from backend.app.infrastructure.database import FindingRepository, NetworkRepository


class DetectionService:
    def __init__(
        self,
        network_repository: NetworkRepository,
        finding_repository: FindingRepository,
        detectors: list[Detector],
    ) -> None:
        self._network_repository = network_repository
        self._finding_repository = finding_repository
        self._detectors = detectors

    def detect(self, analysis_id: str) -> None:
        self._finding_repository.start_detection(analysis_id, datetime.now(UTC))
        try:
            context = DetectionContext(
                analysis_id=analysis_id,
                flows=self._network_repository.list_flows(analysis_id, limit=1_000_000),
                events=self._network_repository.list_events(analysis_id, limit=1_000_000),
            )
            findings = [
                finding
                for detector in self._detectors
                for finding in detector.detect(context)
            ]
            self._finding_repository.save_findings(
                analysis_id,
                findings,
                completed_at=datetime.now(UTC),
            )
        except Exception as exc:
            self._finding_repository.fail_detection(
                analysis_id,
                datetime.now(UTC),
                f"{type(exc).__name__}: {exc}",
            )
            raise

