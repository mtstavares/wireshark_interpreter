from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from time import monotonic

from backend.app.domain.analyses import AnalyzerStatus
from backend.app.domain.network import NetworkEvent, NetworkFlow
from backend.app.infrastructure.database import AnalysisRepository, NetworkRepository
from backend.app.normalization.parsers import (
    merge_flows,
    parse_suricata_directory,
    parse_tshark_directory,
    parse_zeek_directory,
)


class NormalizationService:
    def __init__(
        self,
        analysis_repository: AnalysisRepository,
        network_repository: NetworkRepository,
        analyses_dir: Path,
        timeout_seconds: int,
    ) -> None:
        self._analysis_repository = analysis_repository
        self._network_repository = network_repository
        self._analyses_dir = analyses_dir
        self._timeout_seconds = timeout_seconds

    def normalize(self, analysis_id: str) -> None:
        self._network_repository.start_normalization(analysis_id, datetime.now(UTC))
        try:
            analysis = self._analysis_repository.get(analysis_id)
            if analysis is None:
                raise KeyError(analysis_id)
            completed = {
                run.analyzer
                for run in analysis.analyzer_runs
                if run.status is AnalyzerStatus.COMPLETED
            }
            flows: list[NetworkFlow] = []
            events: list[NetworkEvent] = []
            analysis_dir = self._analyses_dir / analysis_id
            deadline = monotonic() + self._timeout_seconds

            parsers = {
                "zeek": parse_zeek_directory,
                "suricata": parse_suricata_directory,
                "tshark": parse_tshark_directory,
            }
            for analyzer, parser in parsers.items():
                if analyzer not in completed:
                    continue
                parsed_flows, parsed_events = parser(
                    analysis_id,
                    analysis_dir / analyzer,
                    deadline=deadline,
                )
                flows.extend(parsed_flows)
                events.extend(parsed_events)

            correlated_flows = merge_flows(analysis_id, flows, deadline=deadline)
            self._network_repository.save_results(
                analysis_id,
                correlated_flows,
                events,
                completed_at=datetime.now(UTC),
            )
        except Exception as exc:
            self._network_repository.fail_normalization(
                analysis_id,
                datetime.now(UTC),
                f"{type(exc).__name__}: {exc}",
            )
            raise
