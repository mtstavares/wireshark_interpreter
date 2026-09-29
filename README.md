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
  - alertas provenientes do Suricata, quando disponível.
- Inventário de hosts, serviços e contexto de ativos.
- Enriquecimento offline com referências CWE e MITRE ATT&CK.
- Reputação e catálogos locais opcionais, com fonte, validade e cache.
- Relatório JSON e HTML determinístico, sem dependência de LLM.
- Interface de investigação com findings, rede, contexto e timeline.

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

Usuários podem ser exibidos quando observados, mas senhas, tokens e outros
segredos são omitidos. Como SSH e TLS são criptografados, a aplicação não afirma
que houve login ou vazamento quando a captura não oferece evidência suficiente.

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

## Execução local no Windows

### Pré-requisitos

- Python 3.12 ou superior.
- Node.js e npm.
- Wireshark com TShark instalado.

### Instalação

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"

Set-Location frontend
npm.cmd install
npm.cmd run build
Set-Location ..
```

### Inicialização

```powershell
$env:PCAP_TSHARK_BINARY = "C:\Program Files\Wireshark\tshark.exe"
$env:PCAP_NORMALIZATION_TIMEOUT_SECONDS = "900"

.\.venv\Scripts\uvicorn.exe backend.app.main:app
```

Acesse:

- Aplicação: <http://127.0.0.1:8000/>
- API interativa: <http://127.0.0.1:8000/docs>
- Saúde da aplicação: <http://127.0.0.1:8000/healthz>

Use `--reload` somente durante desenvolvimento. Uma recarga automática
interrompe análises em andamento e, por isso, não é recomendada para PCAPs
grandes.

## Contexto e enriquecimento local

Os arquivos em `samples/enrichment` demonstram como adicionar nomes de ativos,
criticidade, allowlist, reputação e catálogo técnico sem enviar dados à internet:

```powershell
$env:PCAP_ASSET_CONTEXT_FILE = "$PWD\samples\enrichment\assets.example.json"
$env:PCAP_REPUTATION_FILE = "$PWD\samples\enrichment\reputation.example.json"
$env:PCAP_ENRICHMENT_CATALOG_FILE = "$PWD\samples\enrichment\catalog.example.json"
```

Esses dados fornecem contexto e nunca confirmam sozinhos um incidente ou alteram
automaticamente a severidade de um finding.

## Execução com Docker

```powershell
docker compose up --build
```

## Qualidade

```powershell
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\pyright.exe
.\.venv\Scripts\pytest.exe --cov=backend.app --cov-report=term-missing

Set-Location frontend
npm.cmd run lint
npm.cmd run test
npm.cmd run build
```

Na criação deste README, o projeto possuía 43 testes backend aprovados e
cobertura superior a 91%, além dos testes e verificações do frontend.

## Limitações atuais

- Apenas o tráfego presente na captura pode ser analisado.
- Conteúdo protegido por SSH ou TLS normalmente não revela credenciais,
  comandos ou payloads.
- Zeek e Suricata são opcionais e podem aparecer como indisponíveis.
- O processamento ainda ocorre no mesmo serviço da API; workers dedicados fazem
  parte da evolução planejada.
- Validação ativa de vulnerabilidades permanece fora do núcleo atual.
- A integração com LLM foi deliberadamente adiada até a consolidação do pipeline
  determinístico.

## Documentação

- [Escopo](docs/01-ESCOPO.md)
- [Arquitetura](docs/02-ARQUITETURA.md)
- [Padrões do projeto](docs/03-PADROES.md)
- [Estratégia futura de LLM e tokens](docs/04-LLM-E-TOKENS.md)
- [Roadmap](docs/05-ROADMAP.md)
- [Plano por sprints](docs/06-SPRINTS.md)
- [Teste manual da Sprint 7](docs/12-TESTE-MANUAL-SPRINT-7.md)
- [Teste com PCAP grande](docs/13-TESTE-PCAP-GRANDE.md)
- [Contrato do relatório](docs/schemas/report.schema.json)
- [Como contribuir](CONTRIBUTING.md)

## Uso responsável

Analise somente capturas e ambientes para os quais você possui autorização.
Arquivos PCAP podem conter informações sensíveis; por isso, capturas locais,
bancos, relatórios e arquivos de ambiente são ignorados pelo Git.

## Próximos passos

- Isolar análises em workers dedicados.
- Evoluir de SQLite para PostgreSQL quando as métricas justificarem.
- Adicionar mais detectores e testes com datasets públicos sanitizados.
- Implementar validação ativa somente com autorização, allowlist e isolamento.
- Avaliar uma camada opcional de LLM para correlação e explicação, sem permitir
  que ela crie fatos ou substitua evidências.

---

Projeto desenvolvido como laboratório prático de análise de tráfego,
engenharia de software segura e resposta a incidentes.
