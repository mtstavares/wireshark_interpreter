import type { ReactNode } from "react";
import { NavLink } from "react-router";

import type { AnalysisStatus, Severity } from "./types";
import { shortId } from "./utils";

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <NavLink className="brand" to="/">
          <span className="brand-mark" aria-hidden="true">PS</span>
          <span>
            <strong>Packet Sentry</strong>
            <small>PCAP Security Analyzer</small>
          </span>
        </NavLink>
        <nav aria-label="Navegação principal">
          <NavLink to="/" end>Visão geral</NavLink>
          <NavLink to="/captures/new">Nova análise</NavLink>
          <NavLink to="/about">Sobre o projeto</NavLink>
        </nav>
        <div className="sidebar-foot">
          <span className="pulse-dot" /> Núcleo determinístico
          <small>Sem LLM · análise offline</small>
        </div>
      </aside>
      <div className="content-shell">
        <header className="topbar">
          <span>Console de investigação</span>
          <a href="/docs" target="_blank" rel="noreferrer">API Docs ↗</a>
        </header>
        <main className="page">{children}</main>
      </div>
    </div>
  );
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {actions && <div className="header-actions">{actions}</div>}
    </header>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const labels: Record<string, string> = {
    queued: "Na fila",
    pending: "Pendente",
    running: "Em execução",
    completed: "Concluída",
    completed_with_warnings: "Com avisos",
    failed: "Falhou",
    canceled: "Cancelada",
    unavailable: "Indisponível",
    timed_out: "Tempo esgotado",
    observed: "Observado",
    inferred: "Inferido",
    signature_match: "Assinatura",
    awaiting_approval: "Aguardando aprovação",
    blocked: "Bloqueada",
    approved: "Aprovada",
  };
  return <span className={`status status-${status}`}>{labels[status] ?? status}</span>;
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`severity severity-${severity}`}>{severity}</span>;
}

export function Metric({ label, value, hint }: { label: string; value: ReactNode; hint?: string }) {
  return (
    <div className="metric-card">
      <span>{label}</span>
      <strong>{value}</strong>
      {hint && <small>{hint}</small>}
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="empty-state">
      <span aria-hidden="true">◎</span>
      <h3>{title}</h3>
      <p>{children}</p>
    </div>
  );
}

export function ErrorState({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : "Erro inesperado";
  return (
    <div className="callout callout-danger" role="alert">
      <strong>Não foi possível carregar esta área.</strong>
      <span>{message}</span>
    </div>
  );
}

export function LoadingState({ label = "Carregando dados…" }: { label?: string }) {
  return <div className="loading"><span className="spinner" /> {label}</div>;
}

export function AnalysisNav({ analysisId, status }: { analysisId: string; status: AnalysisStatus }) {
  const base = `/analyses/${analysisId}`;
  return (
    <div className="analysis-nav-wrap">
      <div className="analysis-identity">
        <span>Análise</span>
        <code>{shortId(analysisId)}</code>
        <StatusBadge status={status} />
      </div>
      <nav className="analysis-nav" aria-label="Seções da análise">
        <NavLink to={base} end>Resumo</NavLink>
        <NavLink to={`${base}/findings`}>Findings</NavLink>
        <NavLink to={`${base}/network`}>Rede</NavLink>
        <NavLink to={`${base}/context`}>Contexto</NavLink>
        <NavLink to={`${base}/validation`}>Validação</NavLink>
        <NavLink to={`${base}/timeline`}>Timeline</NavLink>
        <NavLink to={`${base}/report`}>Relatório</NavLink>
      </nav>
    </div>
  );
}

export function CopyButton({ value }: { value: string }) {
  const copy = () => void navigator.clipboard.writeText(value);
  return <button className="button button-ghost button-small" onClick={copy}>Copiar</button>;
}
