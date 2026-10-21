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
  - payloads HTTP compatíveis com SQL injection, path traversal, XSS e command
    injection, sem afirmar sucesso apenas pelo código HTTP;
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
- Página de cobertura com métricas TP, FP, FN, precisão e recall por detector.
- Execução local por Uvicorn ou executável Windows sem configuração manual.

## Captura de referência

O repositório inclui [`comprehensive-attacks.pcap`](samples/corpus/comprehensive-attacks.pcap),
uma captura sintética e totalmente offline com 367 pacotes. Ela reúne tráfego benigno, scans,
tentativas e sucessos FTP/Telnet, HTTP Basic, SQL injection, XSS, path traversal, command
injection, DNS tunneling, beaconing e sessões SSH criptografadas.

As credenciais são fictícias. Os resultados esperados e o hash da captura ficam em
[`comprehensive-attacks.expected.json`](samples/corpus/comprehensive-attacks.expected.json).
Para reconstruir e validar o corpus:

```powershell
.\.venv\Scripts\python.exe scripts\generate_corpus.py
.\.venv\Scripts\python.exe -m scripts.validate_comprehensive_corpus `
  --output reports\quality-sprint-12.json
```

O validador opera em modo estrito: retorna erro se um finding esperado estiver ausente ou se um
finding inesperado for produzido. O baseline atual contém 23 verdadeiros positivos, nenhum falso
positivo e nenhum falso negativo. Essas métricas se aplicam somente ao corpus versionado.

## Relatório auditável e legível

O relatório começa pela seção **O que aconteceu**, usando frases diretas:

```text
O IP 10.0.0.5 realizou uma possível varredura de 35 portas no IP 10.0.0.20.

O IP 198.51.100.71 teve sucesso ao autenticar via TELNET no IP 10.10.0.22,
usando o usuário operator e senha "Telnet!2026", após 3 tentativas malsucedidas,
usando as senhas "root", "toor" e "123456".
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
seletiva em lotes, paginação, artefato TShark comprimido e SQLite em modo WAL.
Jobs interrompidos são recuperados como falha na próxima inicialização, evitando
análises eternamente marcadas como `running`. A captura sintética abrangente e o
benchmark de 50 MB estão no [roteiro da Sprint 11](docs/19-TESTE-MANUAL-SPRINT-11.md).

A qualidade das regras é acompanhada por uma regressão ponta a ponta do corpus abrangente. A página
**Cobertura** apresenta TP, FP, FN, precisão e recall por detector. O procedimento e suas limitações
estão no [roteiro da Sprint 12](docs/20-TESTE-MANUAL-SPRINT-12.md).

No benchmark local de 50 MB, a Sprint 11 reduziu o pico observado de aproximadamente 2,43 GB para
638 MB, o tempo de 157,3 s para 94,6 s e o diretório de dados de 873 MB para 56,6 MB. Os números
dependem do hardware, do conteúdo da captura e das versões dos analisadores.

## Execução para desenvolvimento

Requisitos: Python 3.12+, Node.js e TShark/Wireshark. Na raiz do projeto:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
npm --prefix frontend install
npm --prefix frontend run build
$env:PCAP_TSHARK_BINARY = "C:\Program Files\Wireshark\tshark.exe"
.\.venv\Scripts\uvicorn.exe backend.app.main:app --reload --port 8000
```

Abra `http://127.0.0.1:8000`. A documentação da API fica em
`http://127.0.0.1:8000/docs` e a cobertura dos detectores em
`http://127.0.0.1:8000/api/v1/quality/coverage`.

Para executar as verificações do projeto:

```powershell
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\pyright.exe backend
npm --prefix frontend test -- --run
npm --prefix frontend run build
```

## Tecnologias

- Python 3.12+, FastAPI, Pydantic e SQLAlchemy.
- SQLite no estágio atual do projeto.
- TShark/Wireshark para extração de pacotes.
- React, TypeScript, Vite e TanStack Query.
- Pytest, Ruff, Pyright, Vitest e ESLint.
- Docker e Docker Compose.

## Executável Windows

O arquivo `release/PCAP-Security-Analyzer.exe` inicia a aplicação diretamente em
`http://127.0.0.1:8000`, abre o navegador e mantém os dados em
`%LOCALAPPDATA%\PCAP Security Analyzer`. Não é necessário instalar Python, Node,
configurar variáveis de ambiente ou executar comandos.

TShark e Suricata são detectados automaticamente no `PATH` e nas instalações
padrão do Windows. A interface inicia mesmo sem eles, mas a análise de pacotes
terá cobertura reduzida. Para reconstruir o executável:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\build_windows_executable.ps1
```

Consulte o [guia do executável Windows](docs/18-EXECUTAVEL-WINDOWS.md).


Projeto desenvolvido como laboratório prático de análise de tráfego,
engenharia de software segura e resposta a incidentes.
