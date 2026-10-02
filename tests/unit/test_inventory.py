from datetime import UTC, datetime
from pathlib import Path

from backend.app.domain.analyses import Analysis, AnalysisStatus
from backend.app.domain.captures import Capture, CaptureFormat, CaptureStatus
from backend.app.domain.network import NetworkFlow
from backend.app.infrastructure.database import (
    AnalysisRepository,
    CaptureRepository,
    NetworkRepository,
    create_database_engine,
    initialize_database,
)


def test_inventory_sorts_identified_and_unidentified_applications(tmp_path: Path) -> None:
    engine = create_database_engine(tmp_path / "app.db")
    initialize_database(engine)
    now = datetime.now(UTC)
    capture = Capture(
        "capture",
        "capture.pcap",
        "capture.pcap",
        "0" * 64,
        24,
        CaptureFormat.PCAP,
        CaptureStatus.VALIDATED,
        now,
    )
    CaptureRepository(engine).add(capture)
    AnalysisRepository(engine).create(
        Analysis("analysis", capture.id, AnalysisStatus.QUEUED, now), ["tshark"]
    )
    flows = [
        NetworkFlow(
            id=f"flow-{index}",
            analysis_id="analysis",
            sources=["test"],
            external_ids=[str(index)],
            start_time=now,
            end_time=now,
            src_ip="10.0.0.1",
            src_port=50_000 + index,
            dest_ip="10.0.0.2",
            dest_port=443,
            transport="tcp",
            application=application,
            src_bytes=60,
            dest_bytes=0,
            src_packets=1,
            dest_packets=0,
            evidence_refs=[f"packet:{index}"],
        )
        for index, application in enumerate((None, "tls"))
    ]
    repository = NetworkRepository(engine)
    repository.save_results("analysis", flows, [], now)

    inventory = repository.inventory("analysis")

    assert [service.application for service in inventory.services] == [None, "tls"]
    engine.dispose()
