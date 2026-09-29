from __future__ import annotations

from datetime import datetime
from html import escape

from backend.app.domain.findings import Severity
from backend.app.domain.network import ServiceInventory
from backend.app.domain.reports import ReportActivity, ReportFinding, SecurityReport


def render_html(report: SecurityReport) -> str:
    findings = "".join(_finding_card(item) for item in report.findings) or (
        '<p class="empty">Nenhum finding produzido pelas regras habilitadas.</p>'
    )
    activities = "".join(_activity_card(item) for item in report.activities) or (
        '<p class="empty">Nenhuma atividade de seguranca foi identificada.</p>'
    )
    hosts = "".join(
        "<tr>"
        f"<td>{escape(host.ip)}</td>"
        f"<td>{host.sent_bytes}</td>"
        f"<td>{host.received_bytes}</td>"
        f"<td>{escape(', '.join(host.applications) or '—')}</td>"
        "</tr>"
        for host in report.hosts
    )
    services = _service_summary(report.services)
    indicators = "".join(
        f"<li><strong>{escape(item.type)}</strong>: <code>{escape(item.value)}</code></li>"
        for item in report.indicators
    ) or "<li>Nenhum indicador derivado dos findings.</li>"
    enrichments = "".join(
        "<tr>"
        f"<td>{escape(item.namespace)}</td>"
        f"<td><code>{escape(item.value)}</code></td>"
        f"<td>{escape(item.title)}</td>"
        f"<td>{escape(item.provider)}</td>"
        f"<td>{'sim' if item.cache_hit else 'não'}</td>"
        "</tr>"
        for item in report.enrichments
    ) or '<tr><td colspan="5">Nenhum enriquecimento disponível.</td></tr>'
    asset_context = "".join(
        "<tr>"
        f"<td>{escape(item.ip)}</td>"
        f"<td>{escape(item.name or '—')}</td>"
        f"<td>{escape(item.scope)}</td>"
        f"<td>{escape(item.criticality or '—')}</td>"
        f"<td>{'sim' if item.allowlisted else 'não'}</td>"
        f"<td>{escape(item.role or '—')}</td>"
        "</tr>"
        for item in report.assets
    )
    timeline = "".join(
        "<li>"
        f"<time>{escape(_date(item.occurred_at))}</time> "
        f'<span class="badge {item.severity.value}">{escape(item.severity.value)}</span> '
        f"{escape(item.title)}"
        "</li>"
        for item in report.timeline
    ) or "<li>Nenhum finding para compor a timeline.</li>"
    analyzers = "".join(
        "<tr>"
        f"<td>{escape(item.name)}</td>"
        f"<td>{escape(item.status.value)}</td>"
        f"<td>{escape(item.version or '—')}</td>"
        f"<td>{escape(item.diagnostic or '—')}</td>"
        "</tr>"
        for item in report.analyzers
    )
    limitations = "".join(f"<li>{escape(item)}</li>" for item in report.limitations)
    severity = "".join(
        f'<div class="metric"><strong>{report.summary.severity_counts[level]}</strong>'
        f"<span>{escape(level.value)}</span></div>"
        for level in Severity
    )
    return f"""<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Relatório de segurança — {escape(report.capture.original_filename)}</title>
  <style>{_CSS}</style>
</head>
<body>
<main>
  <header>
    <p class="eyebrow">PCAP Security Analyzer · relatório {report.schema_version}</p>
    <h1>Relatório de segurança</h1>
    <p>{escape(report.capture.original_filename)} · SHA-256 <code>{report.capture.sha256}</code></p>
    <p class="muted">Análise {report.analysis_id} · gerado em {_date(report.generated_at)}</p>
  </header>
  <section>
    <h2>Resumo executivo</h2>
    <p>{escape(report.executive_summary)}</p>
    <div class="metrics">
      <div class="metric"><strong>{report.summary.host_count}</strong><span>hosts</span></div>
      <div class="metric"><strong>{report.summary.service_count}</strong><span>serviços</span></div>
      <div class="metric"><strong>{report.summary.flow_count}</strong><span>fluxos</span></div>
      <div class="metric"><strong>{report.summary.event_count}</strong><span>eventos</span></div>
      <div class="metric"><strong>{report.summary.enrichment_count}</strong>
      <span>enriquecimentos</span></div>
      {severity}
    </div>
  </section>
  <section>
    <h2>O que aconteceu</h2>
    <p class="muted">Leitura direta dos achados, ligada as evidencias tecnicas abaixo.</p>
    <div class="activities">{activities}</div>
  </section>
  <section><h2>Findings priorizados</h2>{findings}</section>
  <section>
    <h2>Enriquecimento e provenance</h2>
    <div class="table"><table><thead><tr><th>Namespace</th><th>Referência</th>
    <th>Contexto</th><th>Fonte</th><th>Cache</th></tr></thead><tbody>{enrichments}</tbody></table></div>
  </section>
  <section><h2>Timeline</h2><ol class="timeline">{timeline}</ol></section>
  <section>
    <h2>Ativos observados</h2>
    <div class="table"><table><thead><tr><th>IP</th><th>Bytes enviados</th>
    <th>Bytes recebidos</th><th>Aplicações</th></tr></thead><tbody>{hosts}</tbody></table></div>
  </section>
  <section>
    <h2>Contexto dos ativos</h2>
    <div class="table"><table><thead><tr><th>IP</th><th>Nome</th><th>Escopo</th>
    <th>Criticidade</th><th>Allowlist</th><th>Papel</th></tr></thead>
    <tbody>{asset_context}</tbody></table></div>
  </section>
  <section>
    <h2>Resumo dos serviços observados</h2>
    <p class="muted">Principais serviços agrupados por aplicação, porta e transporte.
    O inventário completo permanece disponível no JSON e na API.</p>
    {services}
  </section>
  <section><h2>Indicadores derivados</h2><ul>{indicators}</ul></section>
  <section>
    <h2>Analisadores</h2>
    <div class="table"><table><thead><tr><th>Nome</th><th>Status</th><th>Versão</th>
    <th>Diagnóstico</th></tr></thead><tbody>{analyzers}</tbody></table></div>
  </section>
  <section><h2>Limitações</h2><ul>{limitations}</ul></section>
</main>
</body>
</html>"""


def _service_summary(services: list[ServiceInventory], limit: int = 12) -> str:
    grouped: dict[tuple[int, str, str | None], tuple[set[str], int]] = {}
    for item in services:
        key = (item.port, item.transport, item.application)
        endpoints, flow_count = grouped.get(key, (set(), 0))
        endpoints.add(item.ip)
        grouped[key] = (endpoints, flow_count + item.flow_count)

    ordered = sorted(
        grouped.items(),
        key=lambda item: (-item[1][1], item[0][0], item[0][1], item[0][2] or ""),
    )
    rows = "".join(
        "<tr>"
        f"<td>{escape(application or 'não identificado')}</td>"
        f"<td>{port}/{escape(transport)}</td>"
        f"<td>{len(endpoints)}</td>"
        f"<td>{flow_count}</td>"
        "</tr>"
        for (port, transport, application), (endpoints, flow_count) in ordered[:limit]
    )
    if not rows:
        rows = '<tr><td colspan="4">Nenhum serviço identificado.</td></tr>'
    omitted = max(0, len(ordered) - limit)
    note = (
        f'<p class="muted">{omitted} grupo(s) adicional(is) omitido(s) desta visão resumida.</p>'
        if omitted
        else ""
    )
    return (
        '<div class="table"><table><thead><tr><th>Serviço</th><th>Porta</th>'
        f"<th>Endpoints</th><th>Fluxos</th></tr></thead><tbody>{rows}</tbody></table></div>"
        f"{note}"
    )


def _activity_card(activity: ReportActivity) -> str:
    evidence = "".join(
        f"<code>{escape(reference)}</code>" for reference in activity.evidence_refs[:5]
    )
    destination = escape(activity.destination_ip or "destino nao identificado")
    if activity.destination_port is not None:
        destination += f":{activity.destination_port}"
    return f"""
    <article class="activity">
      <div class="finding-head">
        <span class="badge {activity.severity.value}">{escape(activity.severity.value)}</span>
        <span>{escape(_date(activity.occurred_at))}</span>
        <span>confianca {activity.confidence:.0%}</span>
      </div>
      <p class="activity-statement">{escape(activity.statement)}</p>
      <p class="muted">Origem: <code>{escape(activity.source_ip or 'nao identificada')}</code>
      &rarr; Destino: <code>{destination}</code> &middot;
      classificacao: {escape(activity.assertion_status.value)}</p>
      <details><summary>Ver referencias de evidencia</summary>{evidence}</details>
    </article>"""


def _finding_card(finding: ReportFinding) -> str:
    mitigations = "".join(f"<li>{escape(item)}</li>" for item in finding.mitigations)
    evidence = "".join(
        f"<li>{escape(item.kind)} · {escape(item.source)} · "
        f"<code>{escape(item.reference)}</code></li>"
        for item in finding.evidence
    )
    display_filter = escape(finding.wireshark_filter or "Filtro não disponível")
    return f"""
    <article class="finding {finding.severity.value}">
      <div class="finding-head">
        <span class="badge {finding.severity.value}">{escape(finding.severity.value)}</span>
        <span>confiança {finding.confidence:.0%}</span>
        <span>{escape(finding.assertion_status.value)}</span>
      </div>
      <h3>{escape(finding.title)}</h3>
      <p>{escape(finding.summary)}</p>
      <h4>Filtro Wireshark</h4><pre>{display_filter}</pre>
      <h4>Evidências</h4><ul>{evidence}</ul>
      <h4>Mitigação</h4><ul>{mitigations}</ul>
    </article>"""


def _date(value: datetime | None) -> str:
    if value is None:
        return "horário não disponível"
    return value.isoformat().replace("+00:00", "Z")


_CSS = """
:root {
  color-scheme: dark; --bg: #07111f; --panel: #101d2d; --line: #26384d;
  --text: #e9f0f7; --muted: #9fb0c3; --accent: #55d6be;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font: 15px/1.55 system-ui; }
main { max-width: 1100px; margin: auto; padding: 42px 24px; }
header, section {
  background: var(--panel); border: 1px solid var(--line); border-radius: 14px;
  padding: 24px; margin-bottom: 18px;
}
.activities { display: grid; gap: 12px; }
.activity { border-left: 4px solid var(--accent); background: #0b1725; padding: 16px; }
.activity-statement { font-size: 1.08rem; margin: 10px 0; }
.activity details code { display: block; margin: 6px 0; overflow-wrap: anywhere; }
h1 { font-size: 2.3rem; margin: .15em 0; }
h2 { margin-top: 0; }
h3 { margin-bottom: .4em; }
.eyebrow, .muted { color: var(--muted); }
code, pre { font-family: ui-monospace, monospace; }
code { overflow-wrap: anywhere; }
pre { white-space: pre-wrap; background: #07111f; padding: 12px; border-radius: 8px; }
.metrics { display: flex; flex-wrap: wrap; gap: 10px; }
.metric {
  min-width: 105px; background: #07111f; border-radius: 10px;
  padding: 12px; display: grid;
}
.metric strong { font-size: 1.5rem; }
.metric span { color: var(--muted); }
.finding {
  border-left: 5px solid #6b7d91; padding: 18px; background: #0b1725;
  margin: 14px 0; border-radius: 8px;
}
.finding.high, .finding.critical { border-color: #ff6577; }
.finding.medium { border-color: #ffbd5b; }
.finding.low { border-color: #5aa9ff; }
.finding-head { display: flex; gap: 12px; color: var(--muted); }
.badge { font-weight: 700; text-transform: uppercase; }
.badge.high, .badge.critical { color: #ff8290; }
.badge.medium { color: #ffca75; }
.table { overflow: auto; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 10px; border-bottom: 1px solid var(--line); }
.timeline { padding-left: 22px; }
.timeline li { margin: .55em 0; }
@media print {
  body { background: #fff; color: #111; }
  header, section { break-inside: avoid; background: #fff; border-color: #bbb; }
  .finding, pre, .metric { background: #f5f7f9; color: #111; }
  .muted, .eyebrow, .metric span, .finding-head { color: #444; }
}
"""
