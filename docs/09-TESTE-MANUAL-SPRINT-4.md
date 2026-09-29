# Teste manual da Sprint 4

## Objetivo

Validar a execução dos detectores, a persistência dos findings e os filtros da API. Uma captura analisada antes desta sprint não possui a etapa de detecção; crie uma nova análise.

## 1. Iniciar a API

No PowerShell, na raiz do projeto:

```powershell
$env:PCAP_TSHARK_BINARY = "C:\Program Files\Wireshark\tshark.exe"
.\.venv\Scripts\uvicorn.exe backend.app.main:app --reload
```

Abra `http://127.0.0.1:8000/docs`. A API cria as novas tabelas do SQLite automaticamente ao iniciar.

## 2. Enviar a captura

Em outro PowerShell, use o nome existente no projeto, `teste.pcapng`. Se o seu arquivo estiver como `teste.pcap`, altere apenas a variável.

```powershell
$apiBase = "http://127.0.0.1:8000"
$captureFile = "teste.pcapng"
$upload = curl.exe -s -X POST -F "file=@$captureFile" "$apiBase/api/v1/captures" | ConvertFrom-Json
$upload | Format-List
```

O upload deve retornar um `id`, o hash SHA-256 e `capture_format` igual a `pcapng` ou `pcap`.

## 3. Criar uma nova análise

```powershell
$created = curl.exe -s -X POST "$apiBase/api/v1/captures/$($upload.id)/analyses" | ConvertFrom-Json
$analysisId = $created.id
$analysisId
```

Aguarde a conclusão:

```powershell
do {
    Start-Sleep -Seconds 2
    $analysis = curl.exe -s "$apiBase/api/v1/analyses/$analysisId" | ConvertFrom-Json
    $analysis.status
} while ($analysis.status -in @("queued", "running"))

$analysis | ConvertTo-Json -Depth 8
```

Confirme:

- `normalization.status` igual a `completed`;
- `detection.status` igual a `completed`;
- `detection.finding_count` maior ou igual a zero;
- o status geral pode ser `completed_with_warnings` quando Zeek ou Suricata não estiverem instalados, desde que o TShark tenha concluído.

## 4. Consultar os findings

```powershell
$findings = curl.exe -s "$apiBase/api/v1/analyses/$analysisId/findings?limit=100" | ConvertFrom-Json
$findings | Select-Object severity, confidence, title, source_ip, destination_ip, destination_port
```

Na captura usada durante o desenvolvimento, é provável aparecer uma possível varredura horizontal originada por `10.44.44.21` contra vários destinos na porta `6443`. O resultado depende dos tempos e da quantidade de fluxos efetivamente presentes na captura.

Cada finding deve conter:

- `severity` e `confidence` separadas;
- `assertion_status`, que distingue observação, inferência e assinatura;
- `evidence` apontando para IDs de fluxos ou eventos;
- explicação curta em `summary`;
- recomendações em `mitigations`;
- detector e versão usados para reproduzir o resultado.

## 5. Testar filtros e detalhe

```powershell
$medium = curl.exe -s "$apiBase/api/v1/analyses/$analysisId/findings?severity=medium" | ConvertFrom-Json
$scans = curl.exe -s "$apiBase/api/v1/analyses/$analysisId/findings?category=network-service-scanning" | ConvertFrom-Json

if ($findings.Count -gt 0) {
    $findingId = $findings[0].id
    curl.exe -s "$apiBase/api/v1/findings/$findingId" | ConvertFrom-Json | ConvertTo-Json -Depth 8
}
```

## 6. Validar um finding no Wireshark

Para uma varredura horizontal, use um filtro semelhante a este, substituindo os valores pelo finding:

```text
ip.src == 10.44.44.21 && tcp.dstport == 6443
```

Confirme se existem vários IPs de destino dentro de aproximadamente 60 segundos. Isso reproduz a regra, mas não confirma intenção maliciosa: scanners autorizados, monitoramento e descoberta de serviço podem gerar o mesmo padrão.

## Regras incluídas

- varredura horizontal e vertical;
- força bruta e password spraying;
- autenticação bem-sucedida após falhas;
- uso de portas associadas a protocolos sem criptografia;
- consultas DNS longas ou de alta entropia;
- conexões periódicas compatíveis com beaconing;
- alertas de assinatura do Suricata.

## Limitações desta sprint

- Não há reputação de IP; ela entra na Sprint 7 com fonte e validade explícitas.
- Tráfego criptografado pode ocultar autenticação, conteúdo e resultado da tentativa.
- A detecção de protocolo sem criptografia considera o serviço/porta observado; revise o contexto antes de concluir exposição de credenciais.
- Nenhum teste ativo ou exploração é executado. A validação segura está planejada para a Sprint 8 e exigirá autorização e allowlist.
