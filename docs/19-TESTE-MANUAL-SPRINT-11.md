# Sprint 11 — desempenho e estabilidade

## Entregas

- Corpus sintético abrangente e reproduzível em `samples/corpus/comprehensive-attacks.pcap`.
- Manifesto detalhado dos cenários em `comprehensive-attacks.expected.json`.
- Persistência seletiva de eventos do TShark: pacotes genéricos não ocupam mais uma linha no banco.
- Saída tabular do TShark comprimida em Gzip após a execução.
- Paginação por `limit` e `offset` nas APIs de fluxos e eventos.
- Inventário processado em lotes de 5.000 fluxos, sem corte silencioso em 100.000 registros.
- Uma análise pesada por processo da aplicação para evitar disputa de CPU e memória.
- Cancelamento verificado durante a normalização, além do encerramento dos analisadores.
- Detector determinístico de payloads HTTP para SQL injection, traversal, XSS e command injection.

## Teste rápido da captura-base

Com o servidor parado, execute:

```powershell
.\.venv\Scripts\python.exe -m scripts.validate_comprehensive_corpus
```

O resultado deve informar `compressed_tshark_artifact: true` e listar achados de varredura,
credenciais em texto claro, payloads web, DNS anômalo e beaconing.

## Teste pela interface

1. Inicie `PCAP-Security-Analyzer.exe` ou o Uvicorn.
2. Abra `http://127.0.0.1:8000`.
3. Envie `samples/corpus/comprehensive-attacks.pcap`.
4. Inicie a análise e aguarde a conclusão.
5. Confira no relatório:
   - scan vertical e horizontal por `198.51.100.66`;
   - tentativas FTP do usuário `backup` e sucesso com `Backup!2026`;
   - tentativas Telnet do usuário `operator` e sucesso com `Telnet!2026`;
   - HTTP Basic `admin` / `Admin!2026`;
   - SQL injection, path traversal, XSS e command injection;
   - consultas DNS suspeitas e comunicação periódica.

SSH deve aparecer como comunicação/tentativas inferidas. A captura não revela usuário, senha ou
confirmação criptográfica de sucesso porque esses dados são protegidos pelo próprio SSH.

## Paginação

Teste páginas diferentes na documentação interativa:

```text
GET /api/v1/analyses/{id}/flows?limit=10&offset=0
GET /api/v1/analyses/{id}/flows?limit=10&offset=10
GET /api/v1/analyses/{id}/events?limit=10&offset=0
```

As duas páginas de fluxos não devem repetir o mesmo identificador.

## Benchmark

```powershell
$env:PCAP_TSHARK_BINARY = "C:\Program Files\Wireshark\tshark.exe"
.\.venv\Scripts\python.exe -m scripts.benchmark_captures --sizes-mb 10 50 `
  --output reports\benchmark-sprint-11.json
```

Compare tempo, pico de memória, SQLite e diretório de dados com o benchmark anterior. Para uma
estação de trabalho, os alvos de referência para 50 MB são menos de 1 GB de pico, banco abaixo de
150 MB, dados totais abaixo de 250 MB e conclusão em até 120 segundos. Os valores dependem do
hardware e das versões das ferramentas.

Medição realizada nesta Sprint com TShark local e captura sintética de 50 MB:

| Métrica | Antes | Sprint 11 |
| --- | ---: | ---: |
| Tempo total | 157,3 s | 94,6 s |
| Pico de memória | 2,43 GB | 638 MB |
| SQLite, incluindo WAL/SHM | 375 MB | 618 KB |
| Diretório de dados | 873 MB | 56,6 MB |

O benchmark repete o mesmo SYN para estressar retransmissões. Por isso o banco final contém apenas
o fluxo agregado; o TSV completo do TShark permanece como evidência Gzip.

## Cancelamento

1. Envie uma captura grande e inicie a análise.
2. Durante TShark/Suricata ou normalização, use `POST /api/v1/analyses/{id}/cancel`.
3. Confirme que o estado permanece `canceled` e não volta para `completed`.
