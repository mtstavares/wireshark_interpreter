# Wireshark Interpreter — PCAP Security Analyzer

Aplicação web para transformar capturas `.pcap` e `.pcapng` em uma análise de
segurança legível, reproduzível e ligada às evidências originais.

O projeto nasceu como uma iniciativa de portfólio para aproximar a inspeção de
pacotes do trabalho cotidiano de um analista de cibersegurança. Em vez de exigir
que toda investigação comece pela leitura manual de milhares de pacotes no
Wireshark, a aplicação organiza fluxos, eventos, ativos e comportamentos
suspeitos, produzindo um relatório auditável.

> O sistema auxilia a investigação; ele não substitui a validação humana nem
> comprova comprometimento somente pela presença de um alerta.

## Por que este projeto existe

Capturas de rede contêm informações valiosas, mas podem ser difíceis de
interpretar quando há muitos hosts, protocolos e pacotes. A proposta é reduzir
esse esforço inicial sem esconder a evidência técnica.

No trabalho, a aplicação pode apoiar:

- triagem de incidentes e análise inicial de tráfego;
- identificação de varreduras, abuso de autenticação e protocolos inseguros;
- inventário de hosts, serviços e comunicações;
- priorização de findings por severidade e confiança;
- geração de filtros para validação no Wireshark;
- documentação de evidências, limitações e recomendações de mitigação.

Nos estudos, o projeto permite:

- relacionar pacotes, fluxos, eventos e técnicas de ataque;
- praticar análise de PCAP com resultados reproduzíveis;
- estudar FastAPI, React, SQLAlchemy, processamento assíncrono e segurança;
- comparar a interpretação automatizada com a inspeção manual no Wireshark;
- construir casos demonstráveis para um portfólio de cibersegurança.

## O que a aplicação entrega

- Upload validado de arquivos PCAP e PCAPNG.
- Extração offline com TShark; Zeek e Suricata são integrações opcionais.
- Normalização de pacotes em eventos e fluxos correlacionados.
- Detecção determinística de:
  - varredura vertical de portas;
  - varredura horizontal de hosts;
  - força bruta, password spraying e sucesso após falhas;
  - DNS suspeito e possível beaconing;
  - protocolos em texto claro e versões legadas de SNMP;
  - credenciais e resultado de autenticação em FTP, POP3, IMAP, SMTP, HTTP Basic
    e Telnet, quando a captura contém evidência suficiente;
  - alertas provenientes do Suricata, quando disponível.
- Inventário de hosts, serviços e contexto de ativos.
- Enriquecimento offline com referências CWE e MITRE ATT&CK.
- Reputação e catálogos locais opcionais, com fonte, validade e cache.
- Relatório JSON, HTML e PDF determinístico, com hash de integridade e sem LLM.
- Interface de investigação com findings, rede, contexto e timeline.
- Validação TCP opcional, sem payload, com política deny-by-default, dupla
  aprovação, allowlist e trilha de auditoria.

## Relatório auditável e legível

O relatório começa pela seção **O que aconteceu**, usando frases diretas:

```text
O IP 10.0.0.5 realizou uma possível varredura de 35 portas no IP 10.0.0.20.

O IP 10.0.0.10 teve sucesso ao autenticar via SSH no IP 10.0.0.20,
usando o usuário admin, após 5 tentativas malsucedidas.
```

Cada atividade permanece associada a horário, origem, destino, severidade,
confiança, classificação, finding e referências de evidência. A seção de
serviços mostra somente os grupos mais relevantes; o inventário completo
continua disponível pela API.

No modo forense atual, usuário e senha observados em protocolos de autenticação
sem criptografia são preservados no evento, na API e no relatório. Por isso, o
diretório de dados e os relatórios devem ser tratados como material sensível e a
autenticação HTTP da aplicação deve ser habilitada ao disponibilizá-la em rede.
Como SSH e TLS são criptografados, a aplicação não afirma que conhece suas senhas
nem que houve login quando a captura não oferece evidência suficiente.

Uma política local opcional permite classificar um login bem-sucedido como
autorizado ou não autorizado. Sem essa política, a aplicação mantém a autorização
como desconhecida. Consulte o
[roteiro da Sprint 10](docs/17-TESTE-MANUAL-SPRINT-10.md).

## Pipeline

```text
PCAP/PCAPNG
    │
    ▼
Validação e armazenamento seguro
    │
    ▼
TShark ───── Zeek/Suricata opcionais
    │
    ▼
Normalização de eventos e fluxos
    │
    ▼
Detectores determinísticos
    │
    ▼
Enriquecimento e contexto
    │
    ▼
Relatório HTML/JSON + interface web
```

## Validação ativa segura

A validação fica desabilitada quando `PCAP_VALIDATION_POLICY_FILE` não está
configurado. Quando habilitada em laboratório autorizado, o alvo não é digitado
livremente: ele vem do IP e da porta registrados no finding e precisa coincidir
com a allowlist. O fluxo separa dry-run, aprovação, execução e conclusão humana.
O único validador atual, `tcp-connect`, não envia payload e informa apenas
alcance do serviço, não a existência de uma vulnerabilidade.

Veja a política conservadora de exemplo em
[`samples/validation/policy.example.json`](samples/validation/policy.example.json)
e o [roteiro manual da Sprint 8](docs/14-TESTE-MANUAL-SPRINT-8.md).

Corpus, métricas TP/FP/FN, benchmark, retenção, migrations, autenticação e os
procedimentos de backup estão documentados no
[guia de consolidação operacional](docs/15-CONSOLIDACAO-OPERACIONAL.md).

Para capturas maiores, a normalização utiliza agregação indexada, persistência
em lotes e SQLite em modo WAL. Jobs interrompidos são recuperados como falha na
próxima inicialização, evitando análises eternamente marcadas como `running`.

## Tecnologias

- Python 3.12+, FastAPI, Pydantic e SQLAlchemy.
- SQLite no estágio atual do projeto.
- TShark/Wireshark para extração de pacotes.
- React, TypeScript, Vite e TanStack Query.
- Pytest, Ruff, Pyright, Vitest e ESLint.
- Docker e Docker Compose.


Projeto desenvolvido como laboratório prático de análise de tráfego,
engenharia de software segura e resposta a incidentes.
