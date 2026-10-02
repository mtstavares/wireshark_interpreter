from __future__ import annotations

import base64
import secrets
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import RequestResponseEndpoint

from backend.app.analyzers.command import (
    Analyzer,
    DockerZeekAnalyzer,
    SuricataAnalyzer,
    TsharkAnalyzer,
    ZeekAnalyzer,
)
from backend.app.api.routes import router
from backend.app.application.detect_findings import DetectionService
from backend.app.application.enrich_analysis import EnrichmentService
from backend.app.application.generate_report import ReportService
from backend.app.application.ingest_capture import IngestCaptureService
from backend.app.application.normalize_analysis import NormalizationService
from backend.app.application.run_analysis import AnalysisService
from backend.app.application.validate_finding import ValidationPolicy, ValidationService
from backend.app.core.config import Settings
from backend.app.detection.detectors import CredentialAuthorizationPolicy, default_detectors
from backend.app.infrastructure.database import (
    AnalysisRepository,
    CaptureRepository,
    EnrichmentRepository,
    FindingRepository,
    NetworkRepository,
    ValidationRepository,
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
        validation_repository = ValidationRepository(engine)
        validation_repository.recover_interrupted(datetime.now(UTC))
        enrichment_service = EnrichmentService(
            network_repository=network_repository,
            finding_repository=finding_repository,
            enrichment_repository=enrichment_repository,
            asset_context_path=app_settings.asset_context_path,
            reputation_path=app_settings.reputation_path,
            catalog_path=app_settings.enrichment_catalog_path,
        )
        zeek_analyzer: Analyzer
        if app_settings.zeek_binary.startswith("docker://"):
            zeek_analyzer = DockerZeekAnalyzer(
                app_settings.zeek_binary.removeprefix("docker://"),
                app_settings.analyzer_memory_limit_mb,
                app_settings.analyzer_cpu_limit_seconds,
            )
        else:
            zeek_analyzer = ZeekAnalyzer(
                app_settings.zeek_binary,
                app_settings.analyzer_memory_limit_mb,
                app_settings.analyzer_cpu_limit_seconds,
            )
        configured_analyzers = analyzers or [
            zeek_analyzer,
            SuricataAnalyzer(
                app_settings.suricata_binary,
                app_settings.analyzer_memory_limit_mb,
                app_settings.analyzer_cpu_limit_seconds,
            ),
            TsharkAnalyzer(
                app_settings.tshark_binary,
                app_settings.analyzer_memory_limit_mb,
                app_settings.analyzer_cpu_limit_seconds,
            ),
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
                detectors=default_detectors(
                    credential_policy=CredentialAuthorizationPolicy.load(
                        app_settings.credential_policy_path
                    )
                ),
            ),
            enrichment_service=enrichment_service,
        )
        app.state.network_repository = network_repository
        app.state.finding_repository = finding_repository
        app.state.enrichment_service = enrichment_service
        app.state.validation_service = ValidationService(
            finding_repository=finding_repository,
            validation_repository=validation_repository,
            policy=ValidationPolicy.load(app_settings.validation_policy_path),
        )
        app.state.report_service = ReportService(
            capture_repository=repository,
            analysis_repository=analysis_repository,
            network_repository=network_repository,
            finding_repository=finding_repository,
            enrichment_service=enrichment_service,
            validation_repository=validation_repository,
        )
        yield
        engine.dispose()

    application = FastAPI(
        title="PCAP Security Analyzer",
        version="0.1.0",
        lifespan=lifespan,
    )

    @application.middleware("http")
    async def security_controls(request: Request, call_next: RequestResponseEndpoint) -> Response:
        username = app_settings.auth_username
        password = app_settings.auth_password
        if bool(username) != bool(password):
            return JSONResponse(
                {"detail": "Both PCAP_AUTH_USERNAME and PCAP_AUTH_PASSWORD are required"},
                status_code=503,
            )
        if username and password and request.url.path != "/healthz":
            credentials = _basic_credentials(request.headers.get("Authorization"))
            authenticated = (
                credentials is not None
                and secrets.compare_digest(credentials[0], username)
                and secrets.compare_digest(credentials[1], password)
            )
            if not authenticated:
                return JSONResponse(
                    {"detail": "Authentication required"},
                    status_code=401,
                    headers={"WWW-Authenticate": 'Basic realm="PCAP Security Analyzer"'},
                )
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'none'"
        )
        return response

    application.include_router(router)
    frontend_dir = Path("frontend/dist").resolve()
    if frontend_dir.is_dir():
        application.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
    return application


def _basic_credentials(value: str | None) -> tuple[str, str] | None:
    if value is None or not value.startswith("Basic "):
        return None
    try:
        decoded = base64.b64decode(value[6:], validate=True).decode("utf-8")
        username, password = decoded.split(":", 1)
    except (ValueError, UnicodeDecodeError):
        return None
    return username, password


app = create_app()
