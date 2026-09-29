# Teste manual da Sprint 5

## Objetivo

Validar os relatórios JSON e HTML, sua consistência, seus filtros Wireshark e a ausência de dependência de LLM.

## 1. Iniciar a aplicação

```powershell
$env:PCAP_TSHARK_BINARY = "C:\Program Files\Wireshark\tshark.exe"
.\.venv\Scripts\uvicorn.exe backend.app.main:app --reload
```

Você pode reutilizar uma análise concluída na Sprint 4. Caso necessário, envie `teste.pcapng` e execute uma nova análise pelo Swagger em `http://127.0.0.1:8000/docs`.

## 2. Definir a análise

Substitua o valor pelo identificador retornado ao criar a análise:

```powershell
$apiBase = "http://127.0.0.1:8000"
$analysisId = "SEU_ANALYSIS_ID"
```

Confirme que ela terminou:

```powershell
$analysis = curl.exe -s "$apiBase/api/v1/analyses/$analysisId" | ConvertFrom-Json
$analysis.status
$analysis.detection
```

Se a análise ainda estiver em `queued` ou `running`, os endpoints de relatório retornarão HTTP 409.

## 3. Exportar o JSON

```powershell
curl.exe -s "$apiBase/api/v1/analyses/$analysisId/report" -o relatorio.json
$report = Get-Content -Raw -Encoding utf8 .\relatorio.json | ConvertFrom-Json
$report.summary
$report.findings | Select-Object severity, confidence, title, wireshark_filter
```

Confirme a presença de:

- `schema_version` igual a `1.2` na versão atual (`1.0` na entrega original da Sprint 5);
- metadados e SHA-256 da captura;
- resumo executivo e contagens por severidade;
- analisadores e versões disponíveis;
- hosts, serviços e indicadores derivados;
- findings priorizados com evidências e mitigações;
- timeline e limitações;
- `wireshark_filter` nos findings que possuem IP ou porta.

## 4. Exportar e abrir o HTML

```powershell
curl.exe -s "$apiBase/api/v1/analyses/$analysisId/report.html" -o relatorio.html
Start-Process .\relatorio.html
```

O documento é autocontido: não carrega scripts, fontes ou estilos da internet. Confirme visualmente as seções de resumo, findings, timeline, ativos, serviços, indicadores, analisadores e limitações.

Para gerar PDF manualmente, use a função de impressão do navegador. A exportação PDF nativa será consolidada posteriormente.

## 5. Validar a reprodutibilidade

Gere o mesmo relatório novamente e compare os hashes:

```powershell
curl.exe -s "$apiBase/api/v1/analyses/$analysisId/report" -o relatorio-2.json
Get-FileHash .\relatorio.json, .\relatorio-2.json -Algorithm SHA256
```

Os dois hashes devem ser iguais enquanto os dados da análise e a versão do contrato permanecerem iguais.

## 6. Reproduzir um finding no Wireshark

Copie o valor de `wireshark_filter` de um finding, por exemplo:

```text
ip.src == 10.44.44.21 && (tcp.dstport == 6443 || udp.dstport == 6443)
```

Cole o filtro na barra de filtros do Wireshark e confirme que os pacotes correspondem à origem e à porta descritas. O filtro facilita a auditoria, mas não transforma a inferência em confirmação de ataque.

## 7. Limpeza opcional

Os arquivos exportados ficam na raiz apenas se você executar os comandos acima. Para removê-los:

```powershell
Remove-Item -LiteralPath .\relatorio.json, .\relatorio-2.json, .\relatorio.html
```

## Limitações

- O relatório reflete somente os dados já normalizados e detectados.
- IPs listados como indicadores foram derivados dos findings; nesta sprint, eles não possuem reputação externa.
- TLS, captura incompleta ou analisadores indisponíveis reduzem a visibilidade.
- Nenhuma conclusão é criada por LLM e nenhuma validação ativa é executada.
