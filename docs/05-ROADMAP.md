# Roadmap

## M0 — Fundação

- Estrutura Python e configuração de qualidade.
- Docker Compose e ambiente de desenvolvimento.
- Modelos de domínio e migrations.
- Upload seguro, SHA-256 e metadados do PCAP.
- Fixtures pequenas e reproduzíveis.

Saída: arquivo aceito e job registrado de forma segura.

## M1 — Análise determinística

- Adaptadores Zeek, Suricata e TShark.
- Normalização de fluxos, DNS, HTTP, TLS e alertas.
- Detectores de scan, força bruta, tráfego sem criptografia, DNS anômalo e beaconing.
- Inventário e timeline.
- Relatório JSON/HTML sem LLM.

Saída: MVP técnico utilizável e testável.

## M2 — Interface e investigação

- Dashboard de análises.
- Filtros por host, protocolo, severidade e confiança.
- Visualização de timeline e conversações.
- Filtros reproduzíveis do Wireshark.
- Exportação PDF.

Saída: demonstração adequada para portfólio.

## M3 — Enriquecimento

- NVD/CVE/CPE com cache e provenance.
- Indicadores de ameaça configuráveis.
- Contexto de ativos e allowlists.
- MITRE ATT&CK e CWE.

Saída: findings contextualizados sem misturar reputação com comprovação.

## M4 — Validação segura

- Políticas de autorização e allowlist.
- Sandbox sem privilégios e egress restrito.
- Validadores não destrutivos e aprovados.
- Auditoria e aprovação humana.
- Laboratório de replay/emulação.

Saída: redução controlada de falsos positivos em ambientes autorizados.

## M5 — Consolidação

- Testes de regressão com capturas benignas e maliciosas.
- Medição e redução de falsos positivos.
- Tratamento de falhas, limites de recursos e grandes capturas.
- Revisão de segurança do upload, workers e relatórios.
- Documentação operacional e demonstração reproduzível.

Saída: núcleo determinístico estável, seguro e demonstrável.

## M6 — LLM opcional

- Pacote compacto de evidências.
- Structured Outputs e validação de schema.
- Triagem com modelo econômico e correlação com modelo de maior capacidade.
- Cache, orçamento, métricas e fallback determinístico.
- Suite de avaliações contra relatórios esperados.
- Feature flag desabilitada por padrão.

Saída: explicações melhores sem criar dependência operacional da LLM.

## Backlog posterior

- STIX 2.1 para exportação de indicadores.
- Comparação entre análises.
- Regras personalizadas versionadas.
- Filas distribuídas e armazenamento S3 compatível.
- Integração com SIEM/SOAR.
- Suporte a grandes capturas por particionamento temporal.

## Ordem de prioridade

Confiabilidade e rastreabilidade vêm antes da LLM. A integração só começa após M5 e nunca deve bloquear a produção do relatório determinístico.
