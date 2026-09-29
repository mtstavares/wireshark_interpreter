from __future__ import annotations

from typing import Annotated

from fastapi import (
    APIRouter,
    BackgroundTasks,
    File,
    HTTPException,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import HTMLResponse, JSONResponse

from backend.app.api.schemas import (
    AnalysisResponse,
    AssetContextResponse,
    CaptureResponse,
    EnrichmentResponse,
    FindingResponse,
    NetworkEventResponse,
    NetworkFlowResponse,
    NetworkInventoryResponse,
    ProblemDetail,
    SecurityReportResponse,
)
from backend.app.application.enrich_analysis import EnrichmentService
from backend.app.application.generate_report import (
    ReportNotFoundError,
    ReportNotReadyError,
    ReportService,
)
from backend.app.application.ingest_capture import CaptureIngestionError, IngestCaptureService
from backend.app.application.run_analysis import (
    AnalysisNotFoundError,
    AnalysisService,
    CaptureNotFoundError,
)
from backend.app.domain.findings import Severity
from backend.app.domain.reports import SecurityReport
from backend.app.infrastructure.database import (
    CaptureRepository,
    FindingRepository,
    NetworkRepository,
)
from backend.app.reporting.html import render_html

router = APIRouter()


def _repository(request: Request) -> CaptureRepository:
    return request.app.state.capture_repository


def _ingestion_service(request: Request) -> IngestCaptureService:
    return request.app.state.ingestion_service


def _analysis_service(request: Request) -> AnalysisService:
    return request.app.state.analysis_service


def _network_repository(request: Request) -> NetworkRepository:
    return request.app.state.network_repository


def _finding_repository(request: Request) -> FindingRepository:
    return request.app.state.finding_repository


def _report_service(request: Request) -> ReportService:
    return request.app.state.report_service


def _enrichment_service(request: Request) -> EnrichmentService:
    return request.app.state.enrichment_service


@router.get("/healthz", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.post(
    "/api/v1/captures",
    response_model=CaptureResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        413: {"model": ProblemDetail},
        422: {"model": ProblemDetail},
    },
    tags=["captures"],
)
async def upload_capture(
    request: Request,
    file: Annotated[UploadFile, File(description="PCAP or PCAPNG capture")],
) -> CaptureResponse | JSONResponse:
    try:
        capture = await _ingestion_service(request).execute(file)
    except CaptureIngestionError as exc:
        problem = ProblemDetail(status=exc.status_code, title=exc.title, detail=str(exc))
        return JSONResponse(
            status_code=exc.status_code,
            content=problem.model_dump(mode="json"),
            media_type="application/problem+json",
        )
    return CaptureResponse.from_domain(capture)


@router.get(
    "/api/v1/captures/{capture_id}",
    response_model=CaptureResponse,
    tags=["captures"],
)
def get_capture(capture_id: str, request: Request) -> CaptureResponse:
    capture = _repository(request).get(capture_id)
    if capture is None:
        raise HTTPException(status_code=404, detail="Capture not found")
    return CaptureResponse.from_domain(capture)


@router.get(
    "/api/v1/captures",
    response_model=list[CaptureResponse],
    tags=["captures"],
)
def list_captures(request: Request, limit: int = 50) -> list[CaptureResponse]:
    safe_limit = min(max(limit, 1), 100)
    return [
        CaptureResponse.from_domain(capture)
        for capture in _repository(request).list(safe_limit)
    ]


@router.post(
    "/api/v1/captures/{capture_id}/analyses",
    response_model=AnalysisResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["analyses"],
)
def create_analysis(
    capture_id: str, request: Request, background_tasks: BackgroundTasks
) -> AnalysisResponse:
    service = _analysis_service(request)
    try:
        analysis = service.create(capture_id)
    except CaptureNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Capture not found") from exc
    background_tasks.add_task(service.run, analysis.id)
    return AnalysisResponse.from_domain(analysis)


@router.get(
    "/api/v1/analyses/{analysis_id}",
    response_model=AnalysisResponse,
    tags=["analyses"],
)
def get_analysis(analysis_id: str, request: Request) -> AnalysisResponse:
    try:
        analysis = _analysis_service(request).get(analysis_id)
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Analysis not found") from exc
    return AnalysisResponse.from_domain(analysis)


@router.get(
    "/api/v1/captures/{capture_id}/analyses",
    response_model=list[AnalysisResponse],
    tags=["analyses"],
)
def list_analyses(capture_id: str, request: Request, limit: int = 50) -> list[AnalysisResponse]:
    safe_limit = min(max(limit, 1), 100)
    try:
        analyses = _analysis_service(request).list_for_capture(capture_id, safe_limit)
    except CaptureNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Capture not found") from exc
    return [AnalysisResponse.from_domain(analysis) for analysis in analyses]


@router.get(
    "/api/v1/analyses/{analysis_id}/flows",
    response_model=list[NetworkFlowResponse],
    tags=["network"],
)
def list_flows(analysis_id: str, request: Request, limit: int = 100) -> list[NetworkFlowResponse]:
    try:
        _analysis_service(request).get(analysis_id)
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Analysis not found") from exc
    safe_limit = min(max(limit, 1), 1000)
    return [
        NetworkFlowResponse.model_validate(flow)
        for flow in _network_repository(request).list_flows(analysis_id, safe_limit)
    ]


@router.get(
    "/api/v1/analyses/{analysis_id}/events",
    response_model=list[NetworkEventResponse],
    tags=["network"],
)
def list_events(
    analysis_id: str, request: Request, limit: int = 100
) -> list[NetworkEventResponse]:
    try:
        _analysis_service(request).get(analysis_id)
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Analysis not found") from exc
    safe_limit = min(max(limit, 1), 1000)
    return [
        NetworkEventResponse.model_validate(event)
        for event in _network_repository(request).list_events(analysis_id, safe_limit)
    ]


@router.get(
    "/api/v1/analyses/{analysis_id}/inventory",
    response_model=NetworkInventoryResponse,
    tags=["network"],
)
def get_inventory(analysis_id: str, request: Request) -> NetworkInventoryResponse:
    try:
        _analysis_service(request).get(analysis_id)
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Analysis not found") from exc
    inventory = _network_repository(request).inventory(analysis_id)
    return NetworkInventoryResponse.model_validate(inventory, from_attributes=True)


@router.get(
    "/api/v1/analyses/{analysis_id}/findings",
    response_model=list[FindingResponse],
    tags=["findings"],
)
def list_findings(
    analysis_id: str,
    request: Request,
    severity: Severity | None = None,
    category: str | None = None,
    limit: int = 100,
) -> list[FindingResponse]:
    try:
        _analysis_service(request).get(analysis_id)
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Analysis not found") from exc
    safe_limit = min(max(limit, 1), 1000)
    findings = _finding_repository(request).list(
        analysis_id,
        severity=severity,
        category=category,
        limit=safe_limit,
    )
    return [FindingResponse.from_domain(finding) for finding in findings]


@router.get(
    "/api/v1/findings/{finding_id}",
    response_model=FindingResponse,
    tags=["findings"],
)
def get_finding(finding_id: str, request: Request) -> FindingResponse:
    finding = _finding_repository(request).get(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return FindingResponse.from_domain(finding)


@router.get(
    "/api/v1/analyses/{analysis_id}/enrichments",
    response_model=list[EnrichmentResponse],
    tags=["enrichment"],
)
def list_enrichments(analysis_id: str, request: Request) -> list[EnrichmentResponse]:
    try:
        _analysis_service(request).get(analysis_id)
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Analysis not found") from exc
    return [
        EnrichmentResponse.model_validate(item)
        for item in _enrichment_service(request).list(analysis_id)
    ]


@router.get(
    "/api/v1/analyses/{analysis_id}/assets",
    response_model=list[AssetContextResponse],
    tags=["enrichment"],
)
def list_asset_contexts(analysis_id: str, request: Request) -> list[AssetContextResponse]:
    try:
        _analysis_service(request).get(analysis_id)
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Analysis not found") from exc
    return [
        AssetContextResponse.model_validate(item)
        for item in _enrichment_service(request).assets(analysis_id)
    ]


@router.get(
    "/api/v1/analyses/{analysis_id}/report",
    response_model=SecurityReportResponse,
    tags=["reports"],
)
def get_report(
    analysis_id: str, request: Request, response: Response
) -> SecurityReportResponse:
    report = _generate_report(analysis_id, request)
    response.headers["Content-Disposition"] = (
        f'attachment; filename="analysis-{analysis_id}-report.json"'
    )
    return SecurityReportResponse.from_domain(report)


@router.get(
    "/api/v1/analyses/{analysis_id}/report.html",
    response_class=HTMLResponse,
    tags=["reports"],
)
def get_report_html(analysis_id: str, request: Request) -> HTMLResponse:
    report = _generate_report(analysis_id, request)
    return HTMLResponse(
        render_html(report),
        headers={
            "Content-Disposition": f'inline; filename="analysis-{analysis_id}-report.html"'
        },
    )


def _generate_report(analysis_id: str, request: Request) -> SecurityReport:
    try:
        return _report_service(request).generate(analysis_id)
    except ReportNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Analysis not found") from exc
    except ReportNotReadyError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
