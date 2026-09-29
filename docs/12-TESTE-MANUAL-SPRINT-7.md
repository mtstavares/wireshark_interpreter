# Teste manual da Sprint 7

Este roteiro valida enriquecimento, contexto de ativos, allowlist, cache,
validade e provenance sem usar LLM ou consultar serviços externos.

## 1. Iniciar com os catálogos de exemplo

Pare a instância anterior do Uvicorn com `Ctrl+C`. Na raiz do projeto, execute:

```powershell
$env:PCAP_TSHARK_BINARY = "C:\Program Files\Wireshark\tshark.exe"
$env:PCAP_ASSET_CONTEXT_FILE = "$PWD\samples\enrichment\assets.example.json"
$env:PCAP_REPUTATION_FILE = "$PWD\samples\enrichment\reputation.example.json"
$env:PCAP_ENRICHMENT_CATALOG_FILE = "$PWD\samples\enrichment\catalog.example.json"
.\.venv\Scripts\uvicorn.exe backend.app.main:app --reload
```

Os exemplos são dados demonstrativos. O item de reputação possui veredito
`unknown` e não deve ser interpretado como inteligência real.

## 2. Criar uma nova análise

Abra `http://127.0.0.1:8000/`, envie `teste.pcapng` e aguarde o estado terminal.
É necessário criar uma análise nova: execuções antigas não são modificadas
retroativamente.

O resultado de referência continua com 157 eventos, 32 fluxos, 19 hosts e um
finding de SNMP legado.

## 3. Validar a aba Contexto

Abra **Contexto** e confira:

- referência `CWE-319` ligada ao finding de SNMP legado;
- fonte `builtin-knowledge`, confiança de 99% e influência `context_only`;
- 19 ativos classificados entre `private`, `public`, `multicast` e `link_local`;
- `10.44.44.21` como `estacao-laboratorio`;
- `10.44.44.100` como `dispositivo-snmp` de criticidade alta;
- IPs da rede `10.44.44.0/24` marcados na allowlist;
- reputação local do IP de exemplo com provider, validade e descrição visíveis;
- busca por IP, referência, fonte ou proprietário funcionando.

Contexto e reputação não devem mudar a severidade média, a confiança original
ou o status observado do finding.

## 4. Validar cache

Crie outra análise da mesma captura sem reiniciar a aplicação. Na aba
**Contexto** da segunda execução, o item de reputação ainda válido deve exibir a
marca `cache`. Referências estáticas do catálogo não são contadas como cache de
reputação.

## 5. Validar relatório e API

Na aba **Relatório**, confirme as seções **Enriquecimento e provenance** e
**Contexto dos ativos**. O JSON deve apresentar `schema_version` igual a `1.2`.

Também é possível verificar diretamente:

```text
GET /api/v1/analyses/{analysis_id}/enrichments
GET /api/v1/analyses/{analysis_id}/assets
GET /api/v1/analyses/{analysis_id}/report
```

Cada enriquecimento deve possuir `provider`, `retrieved_at`, `expires_at`,
`cache_hit`, `confidence`, `source_url` e `influence`.

## 6. Verificações automatizadas

```powershell
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\pyright.exe
.\.venv\Scripts\pytest.exe --cov=backend.app --cov-report=term-missing
Set-Location frontend
npm.cmd run lint
npm.cmd run test
npm.cmd run build
```

A sprint é aprovada quando o enriquecimento aparece com provenance, o contexto
de ativos respeita a configuração, a segunda análise demonstra o cache e todas
as verificações terminam sem erro.
