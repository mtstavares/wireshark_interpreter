import { PageHeader } from "../components";

export function AboutPage() {
  return (
    <>
      <PageHeader
        eyebrow="Transparência por projeto"
        title="Sobre o Packet Sentry"
        description="Uma plataforma de triagem forense que preserva a diferença entre fato, inferência e hipótese."
      />
      <div className="about-grid">
        <section className="panel about-hero">
          <p className="eyebrow">Princípio central</p>
          <h2>Evidência antes da conclusão.</h2>
          <p className="lead">
            Cada finding nasce de uma regra determinística, mantém referências para fluxos ou
            eventos e informa separadamente severidade, confiança e status de afirmação.
          </p>
        </section>
        <section className="panel">
          <p className="eyebrow">Pipeline</p>
          <ol className="numbered-list compact">
            <li><strong>Ingestão</strong><span>Validação e SHA-256.</span></li>
            <li><strong>Extração</strong><span>Zeek, Suricata e TShark.</span></li>
            <li><strong>Normalização</strong><span>Fluxos, eventos e ativos.</span></li>
            <li><strong>Detecção</strong><span>Regras versionadas.</span></li>
            <li><strong>Enriquecimento</strong><span>Contexto com fonte e validade.</span></li>
            <li><strong>Relatório</strong><span>JSON e HTML reproduzíveis.</span></li>
          </ol>
        </section>
      </div>
      <div className="three-columns">
        <section className="panel"><h3>Sem LLM no núcleo</h3><p>A versão atual não envia tráfego para provedores de IA. Uma futura integração será opcional e não poderá criar fatos.</p></section>
        <section className="panel"><h3>Validação ativa controlada</h3><p>Desabilitada por padrão. Quando configurada, exige allowlist, autorização em duas etapas e registra toda a execução sem enviar payload.</p></section>
        <section className="panel"><h3>Limitações declaradas</h3><p>TLS, capturas truncadas e ferramentas indisponíveis reduzem a visibilidade. Ausência de finding não prova ausência de ataque.</p></section>
      </div>
      <section className="panel"><h3>Reputação não é prova</h3><p>Referências CWE, CVE, CPE, MITRE ATT&CK e inteligência local preservam fonte, confiança, validade e influência contextual.</p></section>
      <section className="panel">
        <p className="eyebrow">Famílias de detecção</p>
        <div className="capability-grid">
          {["Varredura horizontal e vertical", "Força bruta e password spraying", "Login após falhas", "Protocolos inseguros e SNMP legado", "DNS anômalo", "Beaconing", "Assinaturas Suricata"].map((item) => <span key={item}>✓ {item}</span>)}
        </div>
      </section>
    </>
  );
}
