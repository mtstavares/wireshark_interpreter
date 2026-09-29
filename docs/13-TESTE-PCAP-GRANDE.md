# Teste manual com PCAP grande

Este roteiro valida o endurecimento do pipeline para capturas com muitos pacotes.

## 1. Iniciar em modo estavel

Nao use `--reload` durante este teste, pois uma mudanca de arquivo reinicia o
processo e interrompe a analise.

```powershell
$env:PCAP_TSHARK_BINARY = "C:\Program Files\Wireshark\tshark.exe"
$env:PCAP_NORMALIZATION_TIMEOUT_SECONDS = "900"
.\.venv\Scripts\uvicorn.exe backend.app.main:app
```

Abra `http://127.0.0.1:8000/` e confirme que a pagina carrega.

## 2. Enviar a captura

Envie o PCAP grande pela tela **Nova analise**. Durante o processamento:

- a interface deve continuar respondendo;
- o TShark deve passar para `completed`;
- a normalizacao pode levar mais que no arquivo de demonstracao, mas deve avancar
  para deteccao antes do timeout de 900 segundos;
- Zeek e Suricata podem aparecer como `unavailable` sem impedir o TShark.

Para o arquivo anteriormente observado, com aproximadamente 9,9 MB e 131 mil
pacotes, uma espera superior a dez minutos nao e esperada depois da correcao.

## 3. Validar o resultado

Quando o estado for terminal, confira:

```text
GET /api/v1/analyses/{analysis_id}
GET /api/v1/analyses/{analysis_id}/flows?limit=100
GET /api/v1/analyses/{analysis_id}/events?limit=100
GET /api/v1/analyses/{analysis_id}/findings
GET /api/v1/analyses/{analysis_id}/report
```

O resumo da normalizacao deve conter quantidades maiores que zero. Um estado
`completed_with_warnings` e normal quando somente o TShark esta instalado.

## 4. Validar interrupcao

Opcionalmente, inicie outra analise, encerre o servidor com `Ctrl+C` e inicie-o
novamente. O job interrompido deve aparecer como `failed`, com a mensagem
`Analysis interrupted by an application restart`, e nao ficar eternamente em
`running`.

## 5. Verificacoes automatizadas

```powershell
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\pyright.exe
.\.venv\Scripts\pytest.exe --cov=backend.app --cov-report=term-missing
```
