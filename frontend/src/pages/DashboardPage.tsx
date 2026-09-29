import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";

import { dashboardData } from "../api";
import {
  EmptyState,
  ErrorState,
  LoadingState,
  Metric,
  PageHeader,
  StatusBadge,
} from "../components";
import { formatBytes, formatDate, shortId } from "../utils";

export function DashboardPage() {
  const query = useQuery({
    queryKey: ["dashboard"],
    queryFn: dashboardData,
    refetchInterval: (state) =>
      state.state.data?.analyses.some((item) => ["queued", "running"].includes(item.status))
        ? 2_000
        : false,
  });

  if (query.isPending) return <LoadingState label="Carregando o panorama…" />;
  if (query.isError) return <ErrorState error={query.error} />;

  const { captures, analyses } = query.data;
  const warningCount = analyses.filter((item) => item.status === "completed_with_warnings").length;
  const findingCount = analyses.reduce(
    (total, item) => total + (item.detection?.finding_count ?? 0),
    0,
  );

  return (
    <>
      <PageHeader
        eyebrow="Centro de análise"
        title="Visão geral"
        description="Acompanhe capturas recentes, saúde do pipeline e resultados priorizados."
        actions={<Link className="button button-primary" to="/captures/new">+ Nova análise</Link>}
      />
      <section className="metrics-grid">
        <Metric label="Capturas" value={captures.length} hint="arquivos preservados" />
        <Metric label="Análises" value={analyses.length} hint="execuções recentes" />
        <Metric label="Findings" value={findingCount} hint="regras determinísticas" />
        <Metric label="Com avisos" value={warningCount} hint="pipeline parcial" />
      </section>

      <section className="panel">
        <div className="section-heading">
          <div><p className="eyebrow">Atividade</p><h2>Análises recentes</h2></div>
          <span className="live-label"><span className="pulse-dot" /> atualização automática</span>
        </div>
        {analyses.length === 0 ? (
          <EmptyState title="Nenhuma análise ainda">
            Envie uma captura PCAP ou PCAPNG para iniciar a primeira investigação.
          </EmptyState>
        ) : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Captura</th><th>Análise</th><th>Status</th><th>Findings</th><th>Início</th><th /></tr></thead>
              <tbody>
                {analyses.slice(0, 20).map((analysis) => (
                  <tr key={analysis.id}>
                    <td><strong>{analysis.capture_name}</strong></td>
                    <td><code>{shortId(analysis.id)}</code></td>
                    <td><StatusBadge status={analysis.status} /></td>
                    <td>{analysis.detection?.finding_count ?? "—"}</td>
                    <td>{formatDate(analysis.created_at)}</td>
                    <td><Link className="table-link" to={`/analyses/${analysis.id}`}>Investigar →</Link></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="panel">
        <div className="section-heading"><div><p className="eyebrow">Evidências</p><h2>Capturas armazenadas</h2></div></div>
        <div className="capture-grid">
          {captures.slice(0, 6).map((capture) => (
            <article className="capture-card" key={capture.id}>
              <span className="file-type">{capture.capture_format}</span>
              <h3>{capture.original_filename}</h3>
              <p>{formatBytes(capture.size_bytes)} · {formatDate(capture.created_at)}</p>
              <code title={capture.sha256}>{capture.sha256.slice(0, 20)}…</code>
            </article>
          ))}
        </div>
      </section>
    </>
  );
}
