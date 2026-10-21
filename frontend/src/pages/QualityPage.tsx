import { useQuery } from "@tanstack/react-query";

import { api } from "../api";
import { ErrorState, LoadingState, Metric, PageHeader } from "../components";

const labels: Record<string, string> = {
  "authentication-abuse": "Abuso de autenticação",
  beaconing: "Beaconing",
  "cleartext-credential": "Credenciais em texto claro",
  "cleartext-protocol": "Protocolos sem criptografia",
  "dns-anomaly": "Anomalias DNS",
  "port-scan": "Varreduras",
  "web-attack-payload": "Ataques web",
};

export function QualityPage() {
  const query = useQuery({
    queryKey: ["quality-coverage"],
    queryFn: api.qualityCoverage,
    staleTime: Infinity,
  });

  if (query.isPending) return <LoadingState label="Carregando cobertura…" />;
  if (query.isError) return <ErrorState error={query.error} />;

  const coverage = query.data;
  return (
    <>
      <PageHeader
        eyebrow="Qualidade dos detectores"
        title="Cobertura de regressão"
        description={`Baseline ${coverage.detector_version} validada com ${coverage.capture}.`}
      />
      <section className="metrics-grid">
        <Metric label="Verdadeiros positivos" value={coverage.true_positive} />
        <Metric label="Falsos positivos" value={coverage.false_positive} />
        <Metric label="Falsos negativos" value={coverage.false_negative} />
        <Metric label="Precisão / recall" value={`${coverage.precision * 100}%`} hint={`${coverage.recall * 100}% recall`} />
      </section>
      <section className="panel">
        <div className="section-heading">
          <div><p className="eyebrow">Por família</p><h2>Resultados por detector</h2></div>
          <span>Validado em {coverage.validated_on}</span>
        </div>
        <div className="table-scroll">
          <table>
            <thead><tr><th>Detector</th><th>TP</th><th>FP</th><th>FN</th><th>Precisão</th><th>Recall</th></tr></thead>
            <tbody>
              {coverage.detectors.map((detector) => (
                <tr key={detector.detector}>
                  <td><strong>{labels[detector.detector] ?? detector.detector}</strong><small className="table-subline">{detector.detector}</small></td>
                  <td>{detector.true_positive}</td>
                  <td>{detector.false_positive}</td>
                  <td>{detector.false_negative}</td>
                  <td>{(detector.precision * 100).toFixed(0)}%</td>
                  <td>{(detector.recall * 100).toFixed(0)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      <section className="panel">
        <p className="eyebrow">Escopo da métrica</p>
        <h2>Limitações declaradas</h2>
        <ul className="clean-list">
          {coverage.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}
        </ul>
        <p className="table-subline">SHA-256 da captura: <code>{coverage.capture_sha256}</code></p>
      </section>
    </>
  );
}
