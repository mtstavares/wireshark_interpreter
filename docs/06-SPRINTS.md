# Plano de desenvolvimento por sprints

Cadência sugerida: uma semana por sprint. Cada sprint termina com demonstração, testes e documentação atualizada.

## Progresso

| Sprint | Estado | Evidência |
|---|---|---|
| 1 — Fundação e ingestão | Concluída | Upload, hash, SQLite e testes de integração |
| 2 — Extração e jobs | Concluída | 25 testes totais, 94% de cobertura, smoke test da API aprovado |
| 3 — Normalização | Concluída | Contrato comum, correlação, timeline e inventário |
| 4 — Detectores | Concluída | 6 famílias de regras, findings persistidos e 35 testes |
| 5 — Relatórios | Concluída | JSON/HTML determinísticos, timeline e filtros Wireshark |
| 6 — Interface | Concluída | SPA responsiva, upload, investigação, timeline, relatórios e teste real |
| 7 — Enriquecimento | Concluída | CWE/MITRE/CVE/CPE, contexto de ativos, reputação local, cache e provenance |
| 8 — Validação segura | Concluída | Política deny-by-default, dupla aprovação, teste TCP sem payload e auditoria |
| 9 — Consolidação selecionada | Concluída | Corpus, benchmark, hardening, migrations e relatório final |
| 10 — Autenticação forense | Concluída | Credenciais em texto claro, correlação de respostas e política local |
| LLM opcional | Adiada | Somente após a consolidação |

## Sprint 1 — Fundação e ingestão segura

Objetivo: receber uma captura de maneira segura e registrar sua evidência original.

- Estrutura do backend e configuração por ambiente.
- API de saúde, upload e consulta de captura.
- Validação de extensão e assinatura binária de PCAP/PCAPNG.
- Limite de tamanho durante streaming.
- Nome interno, SHA-256 e armazenamento atômico.
- Metadados em SQLite via SQLAlchemy.
- Testes unitários e de integração.
- Dockerfile e comandos de desenvolvimento.

Critério de aceite: um PCAP válido é armazenado e consultável; formatos inválidos e arquivos acima do limite são rejeitados sem deixar resíduos.

## Sprint 2 — Extração e jobs

Objetivo: executar análise offline e controlar seu ciclo de vida.

- Modelo e estados do job.
- Worker inicial e limites de execução.
- Integração com Zeek, Suricata e TShark.
- Registro de versões, stdout, stderr e duração.
- Persistência das saídas brutas por análise.

Critério de aceite: uma captura gera logs dos três analisadores ou uma falha diagnóstica rastreável.

## Sprint 3 — Normalização e inventário

Objetivo: converter saídas heterogêneas em um domínio comum.

- Eventos, fluxos, hosts e serviços normalizados.
- Correlação por tupla, tempo e IDs nativos.
- Inventário de protocolos e conversações.
- Timeline básica.

Critério de aceite: a API expõe inventário e fluxos sem depender dos formatos nativos dos analisadores.

## Sprint 4 — Detectores essenciais

Objetivo: produzir findings determinísticos e explicáveis.

- Scan horizontal e vertical.
- Força bruta/password spraying.
- Protocolos e autenticação sem criptografia.
- DNS anômalo.
- Beaconing.
- Severidade, confiança e evidências.

Critério de aceite: cada detector possui PCAP positivo, caso benigno e evidência reproduzível.

## Sprint 5 — Relatórios

Objetivo: entregar resultado técnico e executivo sem LLM.

- Resumo da captura.
- Findings priorizados.
- Timeline, ativos e indicadores.
- Explicação e mitigação baseada em templates.
- Exportação JSON e HTML.
- Filtros reproduzíveis para Wireshark.

Critério de aceite: o relatório é compreensível, auditável e idêntico para a mesma entrada e versões.

## Sprint 6 — Interface de investigação

Objetivo: permitir navegação e análise dos resultados.

- Dashboard de análises.
- Upload com progresso.
- Tabelas e filtros.
- Detalhe de finding e evidência.
- Timeline e visualização de conversações.

Critério de aceite: o fluxo principal funciona sem acesso ao terminal.

Resultado: interface React/TypeScript servida pelo próprio FastAPI, com dashboard,
upload por arrastar e soltar, acompanhamento do pipeline, filtros de findings,
inventário de rede, timeline e visualização/download dos relatórios JSON e HTML.
O fluxo completo foi validado com `teste.pcapng` e o roteiro reproduzível está em
[`11-TESTE-MANUAL-SPRINT-6.md`](11-TESTE-MANUAL-SPRINT-6.md).

## Sprint 7 — Enriquecimento

Objetivo: acrescentar contexto sem transformar reputação em prova.

- CVE, CPE, CWE e MITRE ATT&CK.
- Provedores de reputação configuráveis.
- Cache, validade e provenance.
- Contexto de ativos e allowlists.

Critério de aceite: todo dado externo mostra fonte, horário e influência na conclusão.

Resultado: referências do catálogo determinístico e de catálogos locais são
persistidas com fonte, confiança, horário, validade, indicador de cache e influência
`context_only`. O inventário classifica o escopo dos IPs e aceita nomes, papéis,
proprietários, criticidade e allowlists por configuração. Reputação é opcional e
local; nenhum dado de captura é enviado à internet. A interface e o relatório 1.2
exibem o contexto sem alterar automaticamente a severidade ou confirmar incidentes.

## Sprint 8 — Validação segura

Objetivo: reduzir falsos positivos somente em ambientes autorizados.

- Políticas de escopo e allowlist.
- Sandbox e egress restrito.
- Validadores não destrutivos.
- Aprovação humana e auditoria.
- Laboratório de replay/emulação.

Critério de aceite: nenhum destino fora da allowlist pode ser acessado e toda execução é auditável.

Resultado: a aplicação cria primeiro um plano sem tráfego, aceita somente o IP e
a porta exatos do finding e reavalia a política antes de executar. A política é
`deny-by-default`, rejeita nomes DNS e destinos públicos por padrão e exige
allowlist de rede, porta e validador. A execução requer a frase separada
`AUTORIZADO`, faz apenas uma conexão TCP sem payload e grava solicitante,
aprovador, horários, resultado e revisão humana. O resultado de alcance é
contextual: nunca confirma vulnerabilidade nem altera o finding automaticamente.
A interface e o relatório 1.3 exibem todo o fluxo. O roteiro está em
[`14-TESTE-MANUAL-SPRINT-8.md`](14-TESTE-MANUAL-SPRINT-8.md).

Limite consciente: o validador é restrito no nível da aplicação e não executa
comandos arbitrários. Isolamento adicional por processo/container e laboratório
de replay ficam para a consolidação antes de ampliar a biblioteca de validadores.

## Sprint 9 — Consolidação

Objetivo: preparar a versão de portfólio.

- Regressão com corpus benigno e malicioso.
- Desempenho e grandes capturas.
- Revisão de segurança.
- PDF, documentação e demonstração reproduzível.
- Métricas de falsos positivos e cobertura.

Critério de aceite: instalação limpa, demonstração repetível e limitações documentadas.

Resultado do escopo selecionado: corpus PCAP versionado com baseline TP/FP/FN,
benchmark até 50 MiB, cancelamento e limites dos subprocessos, retenção confirmada
por dry-run, autenticação opcional, headers de segurança, testes de entradas
corrompidas e XSS, migrations Alembic, PDF nativo, conclusão, próximos passos e
hash de integridade. O validador ativo ganhou backend Docker sem privilégios em
rede interna sem egress. Consulte
[`15-CONSOLIDACAO-OPERACIONAL.md`](15-CONSOLIDACAO-OPERACIONAL.md).
O teste manual está em
[`16-TESTE-MANUAL-CONSOLIDACAO.md`](16-TESTE-MANUAL-CONSOLIDACAO.md).

## Sprint 10 — Autenticação forense em texto claro

Objetivo: transformar credenciais observáveis e respostas explícitas dos
protocolos em eventos e findings auditáveis.

- Extração seletiva do TShark, sem persistir payload integral.
- Correlação por `tcp.stream` de FTP, POP3, IMAP e SMTP.
- HTTP Basic com resposta conservadora: códigos HTTP isolados não confirmam login.
- Heurística de prompts e respostas explícitas para Telnet.
- Usuário e senha completos nos eventos e relatórios forenses.
- Política opcional para contas, serviços, destinos e redes de origem permitidos.
- Nenhuma tentativa de descriptografar SSH ou TLS.

Critério de aceite: uma troca FTP `USER`/`PASS` seguida de `230` produz um finding
de autenticação bem-sucedida com evidência dos pacotes; política `deny` pode elevar
um sucesso fora das regras para crítico e não há afirmação equivalente para SSH,
TLS ou HTTP ambíguo.

## Sprint futura — LLM opcional

Somente após a consolidação: pacote compacto de evidências, saída estruturada,
orçamento, cache, avaliações e fallback determinístico.
