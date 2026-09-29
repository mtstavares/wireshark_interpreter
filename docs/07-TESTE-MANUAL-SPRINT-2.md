# Teste manual — Sprint 2

## 1. Iniciar a API

```powershell
.\.venv\Scripts\uvicorn.exe backend.app.main:app --reload
```

Abra `http://127.0.0.1:8000/docs`.

## 2. Criar uma captura mínima

Em outro terminal, na raiz do projeto:

```powershell
.\.venv\Scripts\python.exe scripts\create_sample_pcap.py
```

O arquivo será criado em `samples/manual/empty.pcap`. Ele possui cabeçalho PCAP válido e nenhum pacote; serve para validar o pipeline, não as detecções.

## 3. Enviar a captura

Na interface `/docs`, execute `POST /api/v1/captures` e selecione o arquivo criado. Copie o campo `id` da resposta.

Alternativa com PowerShell e `curl.exe`:

```powershell
curl.exe -s -F "file=@samples/manual/empty.pcap" http://127.0.0.1:8000/api/v1/captures
```

## 4. Criar a análise

Na interface `/docs`, execute:

```text
POST /api/v1/captures/{capture_id}/analyses
```

Substitua `{capture_id}` pelo ID recebido. A resposta inicial usa o estado `queued`. Copie o `id` da análise.

## 5. Consultar o resultado

Execute:

```text
GET /api/v1/analyses/{analysis_id}
```

No ambiente Windows atual, o resultado esperado é:

- Análise: `failed`.
- Zeek, Suricata e TShark: `unavailable`.
- Cada execução informa qual binário não foi encontrado.

Isso confirma criação do job, execução em segundo plano, persistência e diagnóstico de pré-requisitos.

## 6. Testar um analisador real

Após instalar o Wireshark com TShark, configure o caminho antes de iniciar a API:

```powershell
$env:PCAP_TSHARK_BINARY = "C:\Program Files\Wireshark\tshark.exe"
.\.venv\Scripts\uvicorn.exe backend.app.main:app --reload
```

Repita os passos 3 a 5. O esperado passa a ser:

- TShark: `completed`, com versão, duração, código `0` e `stdout.log` nos artefatos.
- Zeek e Suricata: `unavailable`, se ainda não estiverem instalados.
- Análise: `completed_with_warnings`.

## 7. Verificar os arquivos

Os resultados ficam em:

```text
.data/analyses/{analysis_id}/{analyzer}/
```

Não edite esses arquivos durante a análise. `stdout.log` e `stderr.log` preservam a saída bruta e o diagnóstico do processo.

## 8. Testes automatizados

```powershell
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\pyright.exe
.\.venv\Scripts\pytest.exe --cov=backend.app --cov-report=term-missing
```

