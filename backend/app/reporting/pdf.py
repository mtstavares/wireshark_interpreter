from __future__ import annotations

from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Flowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from backend.app.domain.reports import SecurityReport


def render_pdf(report: SecurityReport) -> bytes:
    buffer = BytesIO()
    styles = getSampleStyleSheet()
    title = ParagraphStyle("ReportTitle", parent=styles["Title"], alignment=TA_CENTER)
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title="Relatório de segurança PCAP",
        author="PCAP Security Analyzer",
    )
    story: list[Flowable] = [
        Paragraph("Relatório de segurança PCAP", title),
        Spacer(1, 5 * mm),
        Paragraph(f"Captura: {_safe(report.capture.original_filename)}", styles["BodyText"]),
        Paragraph(f"SHA-256: {report.capture.sha256}", styles["Code"]),
        Spacer(1, 5 * mm),
        Paragraph("Resumo executivo", styles["Heading1"]),
        Paragraph(_safe(report.executive_summary), styles["BodyText"]),
        _summary_table(report),
        Paragraph("Findings priorizados", styles["Heading1"]),
    ]
    if report.findings:
        for finding in report.findings:
            story.extend(
                [
                    Paragraph(
                        f"[{finding.severity.value.upper()}] {_safe(finding.title)}",
                        styles["Heading2"],
                    ),
                    Paragraph(_safe(finding.summary), styles["BodyText"]),
                    Paragraph(
                        "Detector: "
                        f"{_safe(finding.detector_name)} "
                        f"v{_safe(finding.detector_version)}",
                        styles["BodyText"],
                    ),
                ]
            )
    else:
        story.append(Paragraph("Nenhum finding produzido.", styles["BodyText"]))
    story.extend(
        [
            Paragraph("Analisadores e versões", styles["Heading1"]),
            _analyzer_table(report),
            Paragraph("Limitações", styles["Heading1"]),
            *[Paragraph(f"• {_safe(item)}", styles["BodyText"]) for item in report.limitations],
            PageBreak(),
            Paragraph("Conclusão e próximos passos", styles["Heading1"]),
            Paragraph(_safe(report.conclusion), styles["BodyText"]),
            *[
                Paragraph(f"{index}. {_safe(item)}", styles["BodyText"])
                for index, item in enumerate(report.next_steps, start=1)
            ],
            Spacer(1, 8 * mm),
            Paragraph("Integridade do relatório", styles["Heading2"]),
            Paragraph("SHA-256 do conteúdo canônico JSON:", styles["BodyText"]),
            Paragraph(report.integrity_sha256, styles["Code"]),
        ]
    )
    document.build(story)
    return buffer.getvalue()


def _summary_table(report: SecurityReport) -> Table:
    data = [
        ["Hosts", "Fluxos", "Eventos", "Findings"],
        [
            str(report.summary.host_count),
            str(report.summary.flow_count),
            str(report.summary.event_count),
            str(report.summary.finding_count),
        ],
    ]
    table = Table(data, repeatRows=1)
    table.setStyle(_table_style())
    return table


def _analyzer_table(report: SecurityReport) -> Table:
    data = [["Analisador", "Status", "Versão"]]
    data.extend([item.name, item.status.value, item.version or "—"] for item in report.analyzers)
    table = Table(data, colWidths=[40 * mm, 40 * mm, 85 * mm], repeatRows=1)
    table.setStyle(_table_style())
    return table


def _table_style() -> TableStyle:
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123047")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]
    )


def _safe(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
