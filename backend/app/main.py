from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from backend.app.analyzers.command import Analyzer, SuricataAnalyzer, TsharkAnalyzer, ZeekAnalyzer
from backend.app.api.routes import router
from backend.app.application.detect_findings import DetectionService
from backend.app.application.enrich_analysis import EnrichmentService
from backend.app.application.generate_report import ReportService
from backend.app.application.ingest_capture import IngestCaptureService
from backend.app.application.normalize_analysis import NormalizationService
from backend.app.application.run_analysis import AnalysisService
from backend.app.core.config import Settings
from backend.app.detection.detectors import default_detectors
from backend.app.infrastructure.database import (
    AnalysisRepository,
    CaptureRepository,
    EnrichmentRepository,
    FindingRepository,
    NetworkRepository,
    create_database_engine,
    initialize_database,
)


def create_app(
    settings: Settings | None = None,
    analyzers: list[Analyzer] | None = None,
) -> FastAPI:
    app_settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
        app_settings.ensure_directories()
        engine = create_database_engine(app_settings.database_path)
        initialize_database(engine)
        repository = CaptureRepository(engine)
        analysis_repository = AnalysisRepository(engine)
        analysis_repository.recover_interrupted(datetime.now(UTC))
        network_repository = NetworkRepository(engine)
        finding_repository = FindingRepository(engine)
        enrichment_repository = EnrichmentRepository(engine)
        enrichment_service = EnrichmentService(
            network_repository=network_repository,
            finding_repository=finding_repository,
            enrichment_repository=enrichment_repository,
            asset_context_path=app_settings.asset_context_path,
            reputation_path=app_settings.reputation_path,
            catalog_path=app_settings.enrichment_catalog_path,
        )
        configured_analyzers = analyzers or [
            ZeekAnalyzer(app_settings.zeek_binary),
            SuricataAnalyzer(app_settings.suricata_binary),
            TsharkAnalyzer(app_settings.tshark_binary),
        ]
        app.state.capture_repository = repository
        app.state.ingestion_service = IngestCaptureService(
            repository=repository,
            captures_dir=app_settings.captures_dir,
            max_upload_bytes=app_settings.max_upload_bytes,
        )
        app.state.analysis_service = AnalysisService(
            capture_repository=repository,
            analysis_repository=analysis_repository,
            analyzers=configured_analyzers,
            captures_dir=app_settings.captures_dir,
            analyses_dir=app_settings.analyses_dir,
            timeout_seconds=app_settings.analyzer_timeout_seconds,
            normalization_service=NormalizationService(
                analysis_repository=analysis_repository,
                network_repository=network_repository,
                analyses_dir=app_settings.analyses_dir,
                timeout_seconds=app_settings.normalization_timeout_seconds,
            ),
            detection_service=DetectionService(
                network_repository=network_repository,
                finding_repository=finding_repository,
                detectors=default_detectors(),
            ),
            enrichment_service=enrichment_service,
        )
        app.state.network_repository = network_repository
        app.state.finding_repository = finding_repository
        app.state.enrichment_service = enrichment_service
        app.state.report_service = ReportService(
            capture_repository=repository,
            analysis_repository=analysis_repository,
            network_repository=network_repository,
            finding_repository=finding_repository,
            enrichment_service=enrichment_service,
        )
        yield
        engine.dispose()

    application = FastAPI(
        title="PCAP Security Analyzer",
        version="0.1.0",
        lifespan=lifespan,
    )
    application.include_router(router)
    frontend_dir = Path("frontend/dist").resolve()
    if frontend_dir.is_dir():
        application.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
    return application


app = create_app()
