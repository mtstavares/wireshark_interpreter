import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link, useParams } from "react-router";

import { api } from "../api";
import {
  AnalysisNav,
  CopyButton,
  EmptyState,
  ErrorState,
  LoadingState,
  Metric,
  PageHeader,
  SeverityBadge,
  StatusBadge,
} from "../components";
import type {
  Analysis,
  AssetContext,
  Enrichment,
  Finding,
  Flow,
  Inventory,
  NetworkEvent,
  SecurityReport,
  Severity,
} from "../types";
import {
  endpoint,
  formatBytes,
  formatDate,
  isPublicIp,
  severityOrder,
  terminalStatuses,
} from "../utils";

type Section = "overview" | "findings" | "network" | "context" | "timeline" | "report";

export function AnalysisPage({ section }: { section: Section }) {
  const { analysisId } = useParams();
  const id = analysisId ?? "";
  const analysisQuery = useQuery({
    queryKey: ["analysis", id],
    queryFn: () => api.analysis(id),
    enabled: Boolean(id),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status && !terminalStatuses.has(status) ? 1_500 : false;
    },
  });
  const analysis = analysisQuery.data;
  const terminal = analysis ? terminalStatuses.has(analysis.status) : false;
  const captureQuery = useQuery({
    queryKey: ["capture", analysis?.capture_id],
    queryFn: () => api.capture(analysis?.capture_id ?? ""),
    enabled: Boolean(analysis?.capture_id),
  });
  const findingsQuery = useQuery({
    queryKey: ["findings", id],
    queryFn: () => api.findings(id),
    enabled: terminal,
  });
  const reportQuery = useQuery({
    queryKey: ["report", id],
    queryFn: () => api.report(id),
    enabled: terminal,
    retry: false,
  });
  const inventoryQuery = useQuery({
    queryKey: ["inventory", id],
    queryFn: () => api.inventory(id),
    enabled: terminal && section === "network",
  });
  const flowsQuery = useQuery({
    queryKey: ["flows", id],
    queryFn: () => api.flows(id),
    enabled: terminal && section === "network",
  });
  const eventsQuery = useQuery({
    queryKey: ["events", id],
    queryFn: () => api.events(id),
    enabled: terminal && section === "timeline",
  });
  const enrichmentsQuery = useQuery({
    queryKey: ["enrichments", id],
    queryFn: () => api.enrichments(id),
    enabled: terminal && section === "context",
  });
  const assetsQuery = useQuery({
    queryKey: ["assets", id],
    queryFn: () => api.assets(id),
    enabled: terminal && section === "context",
  });

  if (!id) return <ErrorState error={new Error("Identificador de análise ausente")} />;
  if (analysisQuery.isPending) return <LoadingState label="Abrindo a investigação…" />;
  if (analysisQuery.isError) return <ErrorState error={analysisQuery.error} />;
  if (!analysis) return <ErrorState error={new Error("A análise não retornou dados")} />;

  return (
    <>
      <PageHeader
        eyebrow="Investigação"
        title={captureQuery.data?.original_filename ?? "Análise de captura"}
        description={`Execução ${id} · criada em ${formatDate(analysis.created_at)}`}
        actions={terminal ? (
          <a className="button button-ghost" href={`/api/v1/analyses/${id}/report.html`} target="_blank" rel="noreferrer">
            Abrir relatório ↗
          </a>
        ) : undefined}
      />
      <AnalysisNav analysisId={id} status={analysis.status} />
      {!terminal && <Pipeline analysis={analysis} />}
      {analysis.error_message && (
        <div className="callout callout-warning"><strong>Execução parcial</strong><span>{analysis.error_message}</span></div>
      )}
      {section === "overview" && (
        <Overview analysis={analysis} report={reportQuery.data} />
      )}
      {section === "findings" && (
        <FindingsView
          findings={findingsQuery.data}
          report={reportQuery.data}
          loading={findingsQuery.isPending && terminal}
          error={findingsQuery.error}
        />
      )}
      {section === "network" && (
        <NetworkView
          inventory={inventoryQuery.data}
          flows={flowsQuery.data}
          loading={inventoryQuery.isPending || flowsQuery.isPending}
          error={inventoryQuery.error ?? flowsQuery.error}
        />
      )}
      {section === "timeline" && (
        <TimelineView
          report={reportQuery.data}
          events={eventsQuery.data}
          loading={eventsQuery.isPending}
          error={eventsQuery.error}
        />
      )}
      {section === "context" && (
        <ContextView
          enrichments={enrichmentsQuery.data}
          assets={assetsQuery.data}
          loading={enrichmentsQuery.isPending || assetsQuery.isPending}
          error={enrichmentsQuery.error ?? assetsQuery.error}
        />
      )}
      {section === "report" && <ReportView analysisId={id} terminal={terminal} />}
    </>
  );
}

function Pipeline({ analysis }: { analysis: Analysis }) {
  const extractionStatus = analysis.analyzer_runs.some((run) => run.status === "running")
    ? "running"
    : analysis.analyzer_runs.every((run) => run.status === "pending")
      ? "pending"
      : "completed";
  const stages = [
    ["Upload", "completed"],
    ["Extração", extractionStatus],
    ["Normalização", analysis.normalization?.status ?? "pending"],
    ["Detecção", analysis.detection?.status ?? "pending"],
    ["Enriquecimento", terminalStatuses.has(analysis.status) ? "completed" : "pending"],
    ["Relatório", "pending"],
  ];
  return (
    <section className="panel pipeline-panel">
      <div className="section-heading"><div><p className="eyebrow">Processamento</p><h2>Análise em andamento</h2></div><span className="spinner" /></div>
      <div className="pipeline">
        {stages.map(([label, status], index) => (
          <div className={`pipeline-step step-${status}`} key={label}>
            <span>{status === "completed" ? "✓" : index + 1}</span>
            <strong>{label}</strong>
            <small>{status}</small>
          </div>
        ))}
      </div>
    </section>
  );
}

function Overview({ analysis, report }: { analysis: Analysis; report?: SecurityReport }) {
  const counts = report?.summary;
  return (
    <>
      <section className="metrics-grid">
        <Metric label="Findings" value={counts?.finding_count ?? analysis.detection?.finding_count ?? 0} hint="priorizados" />
        <Metric label="Hosts" value={counts?.host_count ?? "—"} hint="endereços observados" />
        <Metric label="Fluxos" value={counts?.flow_count ?? analysis.normalization?.flow_count ?? 0} hint="conversações" />
        <Metric label="Eventos" value={counts?.event_count ?? analysis.normalization?.event_count ?? 0} hint="fatos normalizados" />
      </section>
      <div className="two-columns">
        <section className="panel">
          <div className="section-heading"><div><p className="eyebrow">Leitura rápida</p><h2>Resumo executivo</h2></div></div>
          <p className="lead">{report?.executive_summary ?? "O resumo ficará disponível quando a análise terminar."}</p>
          {counts && <SeverityBars counts={counts.severity_counts} />}
        </section>
        <section className="panel">
          <div className="section-heading"><div><p className="eyebrow">Ferramentas</p><h2>Analisadores</h2></div></div>
          <div className="analyzer-list">
            {analysis.analyzer_runs.map((run) => (
              <div key={run.id}>
                <span><strong>{run.analyzer}</strong><small>{run.version ?? run.diagnostic ?? "Sem versão"}</small></span>
                <StatusBadge status={run.status} />
              </div>
            ))}
          </div>
        </section>
      </div>
      {report && report.limitations.length > 0 && (
        <section className="panel">
          <div className="section-heading"><div><p className="eyebrow">Transparência</p><h2>Limitações</h2></div></div>
          <ul className="clean-list">{report.limitations.map((item) => <li key={item}>{item}</li>)}</ul>
        </section>
      )}
    </>
  );
}

function SeverityBars({ counts }: { counts: Record<Severity, number> }) {
  const max = Math.max(1, ...Object.values(counts));
  return (
    <div className="severity-bars">
      {(Object.entries(counts) as Array<[Severity, number]>).map(([severity, count]) => (
        <div key={severity}>
          <span>{severity}</span>
          <div><i className={`bar-${severity}`} style={{ width: `${(count / max) * 100}%` }} /></div>
          <strong>{count}</strong>
        </div>
      ))}
    </div>
  );
}

function FindingsView({
  findings,
  report,
  loading,
  error,
}: {
  findings?: Finding[];
  report?: SecurityReport;
  loading: boolean;
  error: unknown;
}) {
  const [severity, setSeverity] = useState("all");
  const [search, setSearch] = useState("");
  const filtered = useMemo(() => (findings ?? [])
    .filter((item) => severity === "all" || item.severity === severity)
    .filter((item) => `${item.title} ${item.category} ${item.source_ip} ${item.destination_ip}`
      .toLowerCase().includes(search.toLowerCase()))
    .sort((left, right) => severityOrder[left.severity] - severityOrder[right.severity]),
  [findings, search, severity]);

  if (loading) return <LoadingState label="Carregando findings…" />;
  if (error) return <ErrorState error={error} />;
  return (
    <section className="panel">
      <div className="section-heading"><div><p className="eyebrow">Triagem</p><h2>Findings priorizados</h2></div><span>{filtered.length} resultado(s)</span></div>
      <div className="filters">
        <input aria-label="Buscar findings" placeholder="Buscar IP, categoria ou título…" value={search} onChange={(event) => setSearch(event.target.value)} />
        <select aria-label="Filtrar por severidade" value={severity} onChange={(event) => setSeverity(event.target.value)}>
          <option value="all">Todas as severidades</option>
          <option value="critical">Crítica</option><option value="high">Alta</option>
          <option value="medium">Média</option><option value="low">Baixa</option>
          <option value="informational">Informativa</option>
        </select>
      </div>
      {filtered.length === 0 ? <EmptyState title="Nenhum finding encontrado">Ajuste os filtros ou revise as limitações da análise.</EmptyState> : (
        <div className="finding-list">
          {filtered.map((finding) => {
            const reportFinding = report?.findings.find((item) => item.id === finding.id);
            return <FindingCard key={finding.id} finding={finding} filter={reportFinding?.wireshark_filter} />;
          })}
        </div>
      )}
    </section>
  );
}

function FindingCard({ finding, filter }: { finding: Finding; filter?: string | null }) {
  return (
    <details className={`finding-card finding-${finding.severity}`}>
      <summary>
        <SeverityBadge severity={finding.severity} />
        <span><strong>{finding.title}</strong><small>{finding.category} · confiança {(finding.confidence * 100).toFixed(0)}%</small></span>
        <StatusBadge status={finding.assertion_status} />
      </summary>
      <div className="finding-body">
        <p>{finding.summary}</p>
        <dl className="fact-grid">
          <div><dt>Origem</dt><dd>{finding.source_ip ?? "—"}</dd></div>
          <div><dt>Destino</dt><dd>{endpoint(finding.destination_ip, finding.destination_port)}</dd></div>
          <div><dt>Detector</dt><dd>{finding.detector_name} v{finding.detector_version}</dd></div>
          <div><dt>Primeira evidência</dt><dd>{formatDate(finding.first_seen)}</dd></div>
        </dl>
        {filter && <div className="filter-box"><code>{filter}</code><CopyButton value={filter} /></div>}
        <div className="finding-columns">
          <div><h4>Mitigações</h4><ol>{finding.mitigations.map((item) => <li key={item}>{item}</li>)}</ol></div>
          <div><h4>Evidências</h4><ul>{finding.evidence.map((item) => <li key={item.reference}><code>{item.reference}</code> · {item.source}</li>)}</ul></div>
        </div>
      </div>
    </details>
  );
}

function NetworkView({ inventory, flows, loading, error }: { inventory?: Inventory; flows?: Flow[]; loading: boolean; error: unknown }) {
  const [search, setSearch] = useState("");
  if (loading) return <LoadingState label="Montando inventário de rede…" />;
  if (error) return <ErrorState error={error} />;
  if (!inventory || !flows) return null;
  const normalizedSearch = search.toLowerCase();
  const hosts = inventory.hosts.filter((host) => host.ip.toLowerCase().includes(normalizedSearch));
  const visibleFlows = flows.filter((flow) => `${flow.src_ip} ${flow.dest_ip} ${flow.dest_port} ${flow.application}`.toLowerCase().includes(normalizedSearch));
  return (
    <>
      <section className="metrics-grid">
        <Metric label="Hosts" value={inventory.hosts.length} hint="IPs válidos" />
        <Metric label="Públicos" value={inventory.hosts.filter((host) => isPublicIp(host.ip)).length} hint="sem reputação aplicada" />
        <Metric label="Serviços" value={inventory.services.length} hint="IP, porta e transporte" />
        <Metric label="Fluxos" value={flows.length} hint="até 1.000 exibidos" />
      </section>
      <section className="panel">
        <div className="section-heading"><div><p className="eyebrow">Inventário</p><h2>Ativos e conversações</h2></div></div>
        <div className="filters"><input aria-label="Buscar na rede" placeholder="Buscar IP, porta ou aplicação…" value={search} onChange={(event) => setSearch(event.target.value)} /></div>
        <h3>Hosts</h3>
        <div className="table-scroll"><table><thead><tr><th>IP</th><th>Escopo</th><th>Enviado</th><th>Recebido</th><th>Aplicações</th></tr></thead><tbody>
          {hosts.map((host) => <tr key={host.ip}><td><code>{host.ip}</code></td><td><span className="scope-tag">{isPublicIp(host.ip) ? "público" : "privado/local"}</span></td><td>{formatBytes(host.sent_bytes)}</td><td>{formatBytes(host.received_bytes)}</td><td>{host.applications.join(", ") || "—"}</td></tr>)}
        </tbody></table></div>
        <h3 className="subsection-title">Serviços</h3>
        <div className="service-chips">{inventory.services.filter((service) => `${service.ip} ${service.port}`.includes(search)).map((service) => <span key={`${service.ip}:${service.port}:${service.transport}`}><code>{service.ip}:{service.port}</code><small>{service.transport} · {service.application ?? "não identificado"} · {service.flow_count} fluxo(s)</small></span>)}</div>
        <h3 className="subsection-title">Fluxos</h3>
        <div className="table-scroll"><table><thead><tr><th>Horário</th><th>Origem</th><th>Destino</th><th>Protocolo</th><th>Volume</th><th>Fonte</th></tr></thead><tbody>
          {visibleFlows.slice(0, 250).map((flow) => <tr key={flow.id}><td>{formatDate(flow.start_time)}</td><td><code>{endpoint(flow.src_ip, flow.src_port)}</code></td><td><code>{endpoint(flow.dest_ip, flow.dest_port)}</code></td><td>{flow.application ?? flow.transport}</td><td>{formatBytes(flow.src_bytes + flow.dest_bytes)}</td><td>{flow.sources.join(", ")}</td></tr>)}
        </tbody></table></div>
      </section>
    </>
  );
}

function ContextView({
  enrichments,
  assets,
  loading,
  error,
}: {
  enrichments?: Enrichment[];
  assets?: AssetContext[];
  loading: boolean;
  error: unknown;
}) {
  const [search, setSearch] = useState("");
  if (loading) return <LoadingState label="Carregando contexto e provenance…" />;
  if (error) return <ErrorState error={error} />;
  const term = search.toLowerCase();
  const visibleEnrichments = (enrichments ?? []).filter((item) =>
    `${item.namespace} ${item.value} ${item.title} ${item.subject_value} ${item.provider}`
      .toLowerCase().includes(term));
  const visibleAssets = (assets ?? []).filter((item) =>
    `${item.ip} ${item.name} ${item.role} ${item.owner} ${item.labels.join(" ")}`
      .toLowerCase().includes(term));
  return (
    <>
      <section className="metrics-grid">
        <Metric label="Referências" value={enrichments?.length ?? 0} hint="CWE, CVE, CPE, ATT&CK e reputação" />
        <Metric label="Ativos" value={assets?.length ?? 0} hint="contexto inventariado" />
        <Metric label="Allowlist" value={(assets ?? []).filter((item) => item.allowlisted).length} hint="escopo autorizado" />
        <Metric label="Cache" value={(enrichments ?? []).filter((item) => item.cache_hit).length} hint="resultados reaproveitados" />
      </section>
      <section className="panel">
        <div className="section-heading"><div><p className="eyebrow">Contexto verificável</p><h2>Enriquecimento e ativos</h2></div></div>
        <div className="callout"><strong>Contexto não é prova</strong><span>Reputação e referências nunca confirmam um incidente nem alteram a severidade automaticamente.</span></div>
        <div className="filters"><input aria-label="Buscar contexto" placeholder="Buscar IP, referência, fonte ou proprietário…" value={search} onChange={(event) => setSearch(event.target.value)} /></div>
        <h3>Referências e reputação</h3>
        {visibleEnrichments.length === 0 ? <EmptyState title="Nenhum enriquecimento encontrado">O catálogo não encontrou contexto aplicável aos resultados atuais.</EmptyState> : (
          <div className="context-grid">{visibleEnrichments.map((item) => (
            <article key={item.id}>
              <div><span className="scope-tag">{item.namespace}</span>{item.cache_hit && <span className="scope-tag">cache</span>}</div>
              <h4>{item.source_url ? <a href={item.source_url} target="_blank" rel="noreferrer">{item.value} ↗</a> : item.value}</h4>
              <strong>{item.title}</strong><p>{item.description}</p>
              <small>{item.provider} · confiança {(item.confidence * 100).toFixed(0)}% · {item.influence}</small>
            </article>
          ))}</div>
        )}
        <h3 className="subsection-title">Contexto dos ativos</h3>
        <div className="table-scroll"><table><thead><tr><th>IP</th><th>Nome / papel</th><th>Escopo</th><th>Criticidade</th><th>Allowlist</th><th>Proprietário</th><th>Provenance</th></tr></thead><tbody>
          {visibleAssets.map((item) => <tr key={item.ip}><td><code>{item.ip}</code></td><td>{item.name ?? "—"}<small className="table-subline">{item.role ?? item.labels.join(", ")}</small></td><td>{item.scope}</td><td>{item.criticality ?? "—"}</td><td>{item.allowlisted ? "sim" : "não"}</td><td>{item.owner ?? "—"}</td><td>{item.provenance}</td></tr>)}
        </tbody></table></div>
      </section>
    </>
  );
}

function TimelineView({ report, events, loading, error }: { report?: SecurityReport; events?: NetworkEvent[]; loading: boolean; error: unknown }) {
  if (loading) return <LoadingState label="Organizando a timeline…" />;
  if (error) return <ErrorState error={error} />;
  const rows = (events ?? []).slice(0, 300);
  return (
    <section className="panel">
      <div className="section-heading"><div><p className="eyebrow">Sequência temporal</p><h2>Eventos e findings</h2></div><span>{rows.length} eventos exibidos</span></div>
      {report?.timeline.map((item) => <div className="timeline-finding" key={item.finding_id}><time>{formatDate(item.occurred_at)}</time><SeverityBadge severity={item.severity} /><Link to={`/analyses/${report.analysis_id}/findings`}>{item.title}</Link></div>)}
      {rows.length === 0 ? <EmptyState title="Timeline vazia">Nenhum evento normalizado está disponível.</EmptyState> : <div className="timeline-list">
        {rows.map((event) => <article key={event.id}><time>{formatDate(event.occurred_at)}</time><span className="timeline-dot" /><div><strong>{event.application ?? event.event_type}</strong><p>{endpoint(event.src_ip, event.src_port)} → {endpoint(event.dest_ip, event.dest_port)}</p><small>{event.source} · {event.evidence_ref}</small></div></article>)}
      </div>}
    </section>
  );
}

function ReportView({ analysisId, terminal }: { analysisId: string; terminal: boolean }) {
  if (!terminal) return <EmptyState title="Relatório ainda não disponível">Aguarde o término da análise.</EmptyState>;
  const htmlUrl = `/api/v1/analyses/${analysisId}/report.html`;
  const jsonUrl = `/api/v1/analyses/${analysisId}/report`;
  return (
    <section className="panel report-panel">
      <div className="section-heading">
        <div><p className="eyebrow">Exportação</p><h2>Relatório auditável</h2></div>
        <div className="header-actions"><a className="button button-ghost" href={jsonUrl}>Baixar JSON</a><a className="button button-primary" href={htmlUrl} target="_blank" rel="noreferrer">Abrir HTML ↗</a></div>
      </div>
      <iframe title="Prévia do relatório" src={htmlUrl} />
    </section>
  );
}
