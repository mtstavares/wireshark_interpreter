# Padrões do projeto

Os termos **DEVE**, **NÃO DEVE**, **DEVERIA** e **PODE** indicam, respectivamente, requisito, proibição, recomendação e opção.

## Código

### Python

- Python 3.12 ou superior.
- Formatação e lint com Ruff.
- Tipagem estática com Pyright em modo estrito nas camadas de domínio e aplicação.
- Modelos e validação de fronteira com Pydantic.
- Testes com Pytest.
- Funções de domínio não DEVEM depender de FastAPI, banco ou SDKs externos.
- I/O DEVE ser assíncrono apenas onde houver benefício real; processamento de CPU permanece no worker.

### TypeScript

- TypeScript em modo `strict`.
- ESLint e Prettier.
- Componentes funcionais e contratos gerados do OpenAPI quando possível.
- A interface não DEVE recalcular severidade ou confiança.

## Organização

```text
backend/
  api/             # transporte HTTP
  application/     # casos de uso
  domain/          # regras e modelos sem infraestrutura
  infrastructure/  # banco, arquivos, filas e clientes externos
  analyzers/       # adaptadores Zeek/Suricata/TShark
  detectors/       # regras determinísticas
  llm/             # futuro: prompts, schemas, roteamento e métricas
  reporting/       # modelos e renderização
frontend/
rules/
tests/
docs/
```

Dependências apontam para dentro: infraestrutura depende do domínio; o domínio não depende da infraestrutura.

## API

- REST com OpenAPI 3.1.
- Prefixo `/api/v1`.
- Recursos no plural e campos JSON em `snake_case`.
- Erros no formato Problem Details (`application/problem+json`).
- Paginação por cursor para coleções potencialmente grandes.
- `Idempotency-Key` nos endpoints que criam análises.
- Upload com limite configurável e validação por conteúdo, não apenas extensão.

## Dados

- JSON Schema Draft 2020-12 para contratos persistidos ou trocados.
- Datas em RFC 3339, UTC e com sufixo `Z`.
- UUID v4 para identificadores públicos.
- SHA-256 para integridade de arquivos.
- IPs armazenados em representação canônica; portas entre 0 e 65535.
- Valores desconhecidos são `null`, nunca strings como `"N/A"`.
- Unidades aparecem no nome: `duration_ms`, `size_bytes`, `rate_per_minute`.
- Schemas possuem `schema_version` e migração explícita.

## Findings

O contrato canônico está em [`schemas/finding.schema.json`](schemas/finding.schema.json).

### Status de afirmação

- `observed`: diretamente demonstrado no tráfego.
- `inferred`: conclusão apoiada por correlação.
- `signature_match`: assinatura conhecida disparou.
- `potential`: indício que necessita confirmação.
- `confirmed`: confirmado por mecanismo autorizado e registrado.
- `false_positive`: evidência contextual suficiente para rejeitar a hipótese.

### Severidade

`informational`, `low`, `medium`, `high` ou `critical`. Quando houver CVE aplicável, CVSS é armazenado separadamente e sua versão é declarada. Severidade não é copiada automaticamente do CVSS: exposição e contexto do ativo também importam.

### Confiança

Número de `0.0` a `1.0`, calculado por detector. A LLM pode sugerir ajuste, mas o sistema preserva o valor original e a justificativa. O relatório sempre exibe severidade e confiança separadamente.

### Evidência

Todo finding DEVE conter pelo menos uma referência. Evidências podem apontar para
`event_id`, `flow_id`, `packet_number`, log e regra. Payload integral não é
persistido. A exceção explícita é o modo forense de autenticação em texto claro:
usuário e senha extraídos pelos dissectors são preservados para o relatório e
devem ser tratados como evidência sensível.

## Referenciais de segurança

- CVE para identificadores de vulnerabilidade.
- CWE para classes de fraqueza.
- CVSS com versão registrada para pontuação técnica.
- MITRE ATT&CK para técnicas, sem forçar mapeamentos incertos.
- CPE apenas quando fornecedor, produto e versão possuem evidência suficiente.
- STIX 2.1 será considerado na exportação de indicadores após o MVP.

## Segurança da aplicação

- PCAP, nomes de arquivo, payloads, banners e logs são dados não confiáveis.
- Nenhum valor de entrada é interpolado em comando de shell.
- Processos recebem argumentos como lista e usam caminhos internos resolvidos.
- Arquivos extraídos não são executados nem abertos por aplicações do host.
- Containers executam sem privilégios, com filesystem temporário e limites de recursos.
- Segredos operacionais ficam em variáveis de ambiente ou cofre; nunca em logs ou
  repositório. Credenciais observadas no PCAP podem existir no banco e relatório.
- Saída externa é negada por padrão nos workers de análise.
- Relatórios HTML escapam todo conteúdo originado da captura.
- Dados enviados à LLM são minimizados e passam por redação de credenciais.

## Logs e observabilidade

- Logs estruturados em JSON.
- Campos mínimos: `timestamp`, `level`, `service`, `analysis_id`, `event`, `duration_ms`.
- Nunca registrar em logs PCAP, payload integral, senha, token ou chave de API.
  Senhas capturadas ficam restritas aos eventos, findings e relatórios forenses.
- Métricas: duração por fase, arquivos processados, alertas, falhas, tokens, cache hit, custo estimado e versão de ferramenta.
- Cada execução registra versões de Zeek, Suricata, regras, detectores, modelo e prompt.

## Testes

- Unitários para detectores e scoring.
- Contrato para adaptadores e schemas.
- Integração com PCAPs pequenos e conhecidos.
- Golden tests para relatórios e saídas normalizadas.
- Casos benignos são obrigatórios para medir falsos positivos.
- Testes não dependem de internet por padrão.
- Quando a integração futura existir, seus testes usarão respostas gravadas; chamadas reais ficarão em uma suíte manual controlada.

## Git e mudanças

- Commits pequenos no padrão Conventional Commits.
- Branches `feat/`, `fix/`, `docs/`, `test/` e `chore/`.
- Pull requests descrevem motivação, risco, teste e impacto em contratos.
- Mudança incompatível em schema, API ou detector requer versão e nota de migração.
- Decisões arquiteturais relevantes são registradas em `docs/adr/`.
