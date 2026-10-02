from datetime import UTC, datetime, timedelta
from pathlib import Path

from backend.app.application.retention import RetentionService
from backend.app.domain.analyses import Analysis, AnalysisStatus
from backend.app.domain.captures import Capture, CaptureFormat, CaptureStatus
from backend.app.infrastructure.database import (
    AnalysisRepository,
    CaptureRepository,
    create_database_engine,
    initialize_database,
)


def test_retention_dry_run_preserves_active_and_apply_removes_terminal(tmp_path: Path) -> None:
    data = tmp_path / "data"
    captures = data / "captures"
    analyses = data / "analyses"
    captures.mkdir(parents=True)
    analyses.mkdir(parents=True)
    engine = create_database_engine(data / "app.db")
    initialize_database(engine)
    capture_repository = CaptureRepository(engine)
    analysis_repository = AnalysisRepository(engine)
    old = datetime.now(UTC) - timedelta(days=60)
    capture = Capture(
        id="capture-old",
        original_filename="old.pcap",
        stored_filename="capture-old.pcap",
        sha256="0" * 64,
        size_bytes=24,
        capture_format=CaptureFormat.PCAP,
        status=CaptureStatus.VALIDATED,
        created_at=old,
    )
    capture_repository.add(capture)
    analysis = analysis_repository.create(
        Analysis("analysis-old", capture.id, AnalysisStatus.QUEUED, old), ["tshark"]
    )
    capture_path = captures / capture.stored_filename
    capture_path.write_bytes(b"pcap")
    analysis_dir = analyses / analysis.id
    analysis_dir.mkdir()
    (analysis_dir / "artifact.log").write_text("test", encoding="utf-8")
    service = RetentionService(engine, captures, analyses)

    active_plan = service.plan(30)
    assert active_plan.capture_ids == []
    analysis_repository.update_status(
        analysis.id, AnalysisStatus.FAILED, completed_at=datetime.now(UTC)
    )
    plan = service.plan(30)
    assert plan.capture_ids == [capture.id]
    assert plan.analysis_ids == [analysis.id]
    assert capture_path.exists()

    service.apply(plan)

    assert capture_repository.get(capture.id) is None
    assert analysis_repository.get(analysis.id) is None
    assert not capture_path.exists()
    assert not analysis_dir.exists()
    engine.dispose()
