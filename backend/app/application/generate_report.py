from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import asdict, replace
from datetime import datetime
from hashlib import sha256
from ipaddress import ip_address
from uuid import NAMESPACE_URL, uuid5

from backend.app.application.enrich_analysis import EnrichmentService
from backend.app.domain.analyses import Analysis, AnalysisStatus, AnalyzerStatus
from backend.app.domain.captures import Capture
from backend.app.domain.enrichment import AssetContext, Enrichment
from backend.app.domain.findings import DetectionStatus, Finding, Severity
from backend.app.domain.network import NetworkInventory
from backend.app.domain.reports import (
    ReportActivity,
    ReportAnalyzer,
    ReportCapture,
    ReportFinding,
    ReportIndicator,
    ReportSummary,
    ReportTimelineEntry,
    SecurityReport,
)
from backend.app.domain.validation import Validation
from backend.app.infrastructure.database import (
    AnalysisRepository,
    CaptureRepository,
    FindingRepository,
    NetworkRepository,
    ValidationRepository,
)

REPORT_SCHEMA_VERSION = "1.4"
MAX_REPORT_FINDINGS = 10_000


class ReportNotFoundError(Exception):
    pass


class ReportNotReadyError(Exception):
    pass


class ReportService:
    def __init__(
        self,
        capture_repository: CaptureRepository,
        analysis_repository: AnalysisRepository,
        network_repository: NetworkRepository,
        finding_repository: FindingRepository,
        enrichment_service: EnrichmentService,
        validation_repository: ValidationRepository,
    ) -> None:
        self._capture_repository = capture_repository
        self._analysis_repository = analysis_repository
        self._network_repository = network_repository
        self._finding_repository = finding_repository
        self._enrichment_service = enrichment_service
        self._validation_repository = validation_repository

    def generate(self, analysis_id: str) -> SecurityReport:
        analysis = self._analysis_repository.get(analysis_id)
        if analysis is None:
            raise ReportNotFoundError(analysis_id)
        if analysis.status in {AnalysisStatus.QUEUED, AnalysisStatus.RUNNING}:
            raise ReportNotReadyError("Analysis has not reached a terminal state")
        if analysis.detection is not None and analysis.detection.status in {
            DetectionStatus.PENDING,
            DetectionStatus.RUNNING,
        }:
            raise ReportNotReadyError("Detection has not completed")

        capture = self._capture_repository.get(analysis.capture_id)
        if capture is None:
            raise ReportNotFoundError(analysis.capture_id)
        inventory = self._network_repository.inventory(analysis_id)
        findings = self._finding_repository.list(analysis_id, limit=MAX_REPORT_FINDINGS)
        validations = self._validation_repository.list(analysis_id)
        return _build_report(
            capture,
            analysis,
            inventory,
            findings,
            self._enrichment_service.list(analysis_id),
            self._enrichment_service.assets(analysis_id),
            validations,
        )


def _build_report(
    capture: Capture,
    analysis: Analysis,
    inventory: NetworkInventory,
    findings: list[Finding],
    enrichments: list[Enrichment],
    assets: list[AssetContext],
    validations: list[Validation],
) -> SecurityReport:
    report_findings = [_report_finding(finding) for finding in findings]
    severity_counts = {severity: 0 for severity in Severity}
    for finding in findings:
        severity_counts[finding.severity] += 1
    observed_times = [
        value
        for finding in findings
        for value in (finding.first_seen, finding.last_seen)
        if value is not None
    ]
    observed_times.extend(
        value for host in inventory.hosts for value in (host.first_seen, host.last_seen)
    )
    normalization = analysis.normalization
    generated_at = analysis.completed_at or analysis.started_at or analysis.created_at
    summary = ReportSummary(
        flow_count=normalization.flow_count if normalization else 0,
        event_count=normalization.event_count if normalization else 0,
        host_count=len(inventory.hosts),
        service_count=len(inventory.services),
        finding_count=len(findings),
        enrichment_count=len(enrichments),
        severity_counts=severity_counts,
        first_seen=min(observed_times, default=None),
        last_seen=max(observed_times, default=None),
    )
    report = SecurityReport(
        schema_version=REPORT_SCHEMA_VERSION,
        report_id=str(uuid5(NAMESPACE_URL, f"report:{analysis.id}:{REPORT_SCHEMA_VERSION}")),
        generated_at=generated_at,
        analysis_id=analysis.id,
        analysis_status=analysis.status,
        capture=ReportCapture(
            id=capture.id,
            original_filename=capture.original_filename,
            sha256=capture.sha256,
            size_bytes=capture.size_bytes,
            capture_format=capture.capture_format.value,
        ),
        executive_summary=_executive_summary(summary),
        conclusion=_conclusion(summary, analysis),
        next_steps=_next_steps(findings, analysis),
        integrity_sha256="",
        summary=summary,
        analyzers=[
            ReportAnalyzer(
                name=run.analyzer,
                status=run.status,
                version=run.version,
                diagnostic=run.diagnostic,
            )
            for run in analysis.analyzer_runs
        ],
        activities=[_report_activity(finding) for finding in findings],
        findings=report_findings,
        hosts=inventory.hosts,
        services=inventory.services,
        timeline=[
            ReportTimelineEntry(
                occurred_at=finding.first_seen,
                finding_id=finding.id,
                severity=finding.severity,
                title=finding.title,
            )
            for finding in sorted(
                findings,
                key=lambda item: (item.first_seen is None, item.first_seen or generated_at),
            )
        ],
        indicators=_indicators(findings),
        enrichments=enrichments,
        assets=assets,
        validations=validations,
        limitations=_limitations(analysis, validations),
    )
    return replace(report, integrity_sha256=_integrity_hash(report))


def _integrity_hash(report: SecurityReport) -> str:
    payload = asdict(report)
    payload.pop("integrity_sha256", None)
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=lambda value: (
            value.isoformat().replace("+00:00", "Z") if isinstance(value, datetime) else str(value)
        ),
    ).encode("utf-8")
    return sha256(canonical).hexdigest()


def _conclusion(summary: ReportSummary, analysis: Analysis) -> str:
    unavailable = [
        run.analyzer for run in analysis.analyzer_runs if run.status is not AnalyzerStatus.COMPLETED
    ]
    if summary.finding_count == 0:
        conclusion = "Não foram identificados comportamentos cobertos pelas regras habilitadas."
    else:
        priority = sum(
            summary.severity_counts[level] for level in (Severity.CRITICAL, Severity.HIGH)
        )
        conclusion = (
            f"Foram identificados {summary.finding_count} finding(s), sendo {priority} de "
            "prioridade alta ou crítica."
        )
    if unavailable:
        conclusion += " A conclusão possui visibilidade reduzida por analisadores incompletos."
    return conclusion


def _next_steps(findings: list[Finding], analysis: Analysis) -> list[str]:
    steps = [
        "Preservar o PCAP original e verificar seu SHA-256 antes de compartilhar a evidência.",
        "Revisar filtros Wireshark e referências dos findings antes de responder ao incidente.",
    ]
    if any(item.severity in {Severity.CRITICAL, Severity.HIGH} for item in findings):
        steps.insert(0, "Priorizar a validação contextual dos findings altos e críticos.")
    if any(run.status is not AnalyzerStatus.COMPLETED for run in analysis.analyzer_runs):
        steps.append("Reexecutar a análise com os analisadores indisponíveis ou incompletos.")
    return steps


def _report_finding(finding: Finding) -> ReportFinding:
    return ReportFinding(
        id=finding.id,
        title=finding.title,
        category=finding.category,
        severity=finding.severity,
        confidence=finding.confidence,
        assertion_status=finding.assertion_status,
        summary=finding.summary,
        first_seen=finding.first_seen,
        last_seen=finding.last_seen,
        source_ip=finding.source_ip,
        destination_ip=finding.destination_ip,
        destination_port=finding.destination_port,
        evidence=finding.evidence,
        mitigations=finding.mitigations,
        mitre_attack=finding.mitre_attack,
        detector_name=finding.detector_name,
        detector_version=finding.detector_version,
        wireshark_filter=_wireshark_filter(finding),
    )


def _report_activity(finding: Finding) -> ReportActivity:
    return ReportActivity(
        occurred_at=finding.first_seen,
        finding_id=finding.id,
        severity=finding.severity,
        assertion_status=finding.assertion_status,
        statement=finding.summary,
        source_ip=finding.source_ip,
        destination_ip=finding.destination_ip,
        destination_port=finding.destination_port,
        confidence=finding.confidence,
        evidence_refs=[item.reference for item in finding.evidence],
    )


def _executive_summary(summary: ReportSummary) -> str:
    if summary.finding_count == 0:
        return (
            "Nenhum finding foi produzido pelas regras habilitadas. Isso não comprova ausência "
            "de atividade maliciosa; considere as limitações da captura e dos analisadores."
        )
    priority = sum(
        summary.severity_counts[severity] for severity in (Severity.CRITICAL, Severity.HIGH)
    )
    if priority:
        return (
            f"A análise produziu {summary.finding_count} finding(s), incluindo {priority} de "
            "prioridade alta ou crítica. Revise primeiro esses itens e valide suas evidências."
        )
    return (
        f"A análise produziu {summary.finding_count} finding(s), sem itens de severidade alta "
        "ou crítica. Os resultados ainda exigem validação contextual."
    )


def _wireshark_filter(finding: Finding) -> str | None:
    terms: list[str] = []
    if finding.source_ip:
        terms.append(f"{_ip_field(finding.source_ip, 'src')} == {finding.source_ip}")
    if finding.destination_ip:
        terms.append(f"{_ip_field(finding.destination_ip, 'dst')} == {finding.destination_ip}")
    if finding.destination_port is not None:
        terms.append(
            f"(tcp.dstport == {finding.destination_port} || "
            f"udp.dstport == {finding.destination_port})"
        )
    return " && ".join(terms) or None


def _ip_field(value: str, direction: str) -> str:
    try:
        version = ip_address(value).version
    except ValueError:
        version = 4
    return f"{'ipv6' if version == 6 else 'ip'}.{direction}"


def _indicators(findings: list[Finding]) -> list[ReportIndicator]:
    references: dict[tuple[str, str], set[str]] = defaultdict(set)
    for finding in findings:
        if finding.source_ip:
            references[("ip", finding.source_ip)].add(finding.id)
        if finding.destination_ip:
            references[("ip", finding.destination_ip)].add(finding.id)
        for technique in finding.mitre_attack:
            references[("mitre_attack", technique)].add(finding.id)
    return [
        ReportIndicator(type=kind, value=value, finding_ids=sorted(finding_ids))
        for (kind, value), finding_ids in sorted(references.items())
    ]


def _limitations(analysis: Analysis, validations: list[Validation]) -> list[str]:
    limitations = [
        "Credenciais observadas em protocolos sem criptografia podem ser reproduzidas "
        "integralmente; trate este relatório como evidência sensível.",
        "A captura representa somente o tráfego observado e pode estar incompleta ou truncada.",
        "Conteúdo protegido por TLS pode ocultar autenticação, comandos e dados transferidos.",
        "Findings inferidos e assinaturas exigem validação contextual antes de resposta ativa.",
    ]
    if validations:
        limitations.append(
            "Uma conexão TCP valida somente alcançabilidade; não confirma exploração nem "
            "vulnerabilidade e não altera findings automaticamente."
        )
    else:
        limitations.append(
            "Nenhuma exploração ou validação ativa foi executada por este relatório."
        )
    unavailable = [
        run.analyzer for run in analysis.analyzer_runs if run.status is not AnalyzerStatus.COMPLETED
    ]
    if unavailable:
        limitations.append(
            "Analisadores sem resultado completo: " + ", ".join(sorted(unavailable)) + "."
        )
    return limitations
