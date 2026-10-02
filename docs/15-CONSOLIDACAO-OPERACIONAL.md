# Consolidação operacional

## Corpus e métricas

O corpus versionado está em `samples/corpus`. Cada PCAP é sintético, inofensivo
e possui resultado esperado em `manifest.json`.

```powershell
.\.venv\Scripts\python.exe -m scripts.generate_corpus
.\.venv\Scripts\python.exe -m scripts.evaluate_corpus
```

A unidade de avaliação é a categoria esperada por captura. A linha de base atual
é TP=4, FP=1 e FN=0, com precisão 0,80 e recall 1,00. O falso positivo conhecido
é a regularidade artificial de `benign-https.pcap`, interpretada como beaconing;
ele foi preservado para impedir que a métrica seja artificialmente perfeita.

## Benchmark de capturas grandes

O benchmark gera os arquivos em diretório temporário, passa pelo upload, TShark,
normalização, detecção e banco, e registra tempo, pico de RSS, tamanho do SQLite e
uso total em disco.

```powershell
$env:PCAP_TSHARK_BINARY = "C:\Program Files\Wireshark\tshark.exe"
.\.venv\Scripts\python.exe -m scripts.benchmark_captures --sizes-mb 1 10 50
```

O resultado fica em `reports/benchmark.json`. Ajuste os limites com
`PCAP_ANALYZER_TIMEOUT_SECONDS`, `PCAP_ANALYZER_MEMORY_LIMIT_MB` e
`PCAP_ANALYZER_CPU_LIMIT_SECONDS`. Análises em fila ou execução podem ser
canceladas pela interface ou por `POST /api/v1/analyses/{id}/cancel`.

Baseline medido neste host em 2 de outubro de 2026:

| Entrada | Tempo | Pico RSS | SQLite | Dados totais |
|---:|---:|---:|---:|---:|
| 1 MiB | 2,793 s | 220 MB | 7,6 MB | 18,1 MB |
| 5 MiB | 13,562 s | 343 MB | 45,0 MB | 97,8 MB |
| 10 MiB | 29,158 s | 571 MB | 120,1 MB | 238,4 MB |
| 50 MiB | 157,273 s | 2,43 GB | 375,2 MB | 872,7 MB |

Os resultados mostram que a normalização e a persistência, não apenas o TShark,
dominam memória e disco em capturas densas. Para 50 MiB ou mais, reserve ao menos
3 GB de RAM e 1 GB de disco por job, evite análises concorrentes e monitore o
diretório de dados. Os números variam conforme densidade de pacotes e hardware.

## Retenção e limpeza

A limpeza nunca ocorre implicitamente. Primeiro execute o dry-run:

```powershell
.\.venv\Scripts\python.exe -m scripts.retention --days 30
```

Revise todos os caminhos e só então confirme:

```powershell
.\.venv\Scripts\python.exe -m scripts.retention --days 30 --apply
```

Capturas com análises ativas são excluídas do plano. Arquivos e diretórios só
podem ser removidos dentro de `.data/captures` e `.data/analyses`.

## Banco: migration, backup e restauração

O startup executa migrations Alembic até `head`; não usa mais `create_all`
diretamente. Antes de manutenção, pare o Uvicorn e faça backup consistente:

```powershell
Copy-Item .data\app.db .data\app.backup.db
Copy-Item .data\captures .data\captures.backup -Recurse
Copy-Item .data\analyses .data\analyses.backup -Recurse
```

Para restaurar, mantenha a aplicação parada, renomeie o diretório `.data` atual
e recoloque banco, capturas e análises do mesmo backup. Não restaure apenas o
banco sem os artefatos correspondentes. SQLite permanece adequado para uma
instância e um worker; PostgreSQL passa a ser recomendado com múltiplos workers
ou usuários concorrentes.

## Autenticação e headers

Quando a aplicação for exposta em rede, configure ambos:

```powershell
$env:PCAP_AUTH_USERNAME = "analista"
$env:PCAP_AUTH_PASSWORD = "use-um-segredo-longo"
```

Isso habilita HTTP Basic para interface, API e documentação, mantendo apenas
`/healthz` público. Use sempre HTTPS em um proxy reverso; Basic sem TLS não
protege a senha. A aplicação adiciona CSP, `nosniff`, `SAMEORIGIN` e política de
referência. Os relatórios escapam conteúdo não confiável e possuem testes XSS.

## Validação isolada e egress

O backend padrão de validação ativa agora é `docker`. Construa a imagem e a rede:

```powershell
.\scripts\setup_validation_sandbox.ps1
```

O runner usa filesystem somente leitura, usuário sem privilégios, sem
capabilities, limite de memória/CPU/PIDs e a rede Docker `internal`, sem saída
para internet. Somente alvos de laboratório ligados explicitamente a essa rede
podem ser alcançados. O backend `process` existe apenas para testes automatizados
e não deve ser usado em produção.

Não adicione novos validadores até que o ambiente Docker esteja operacional e o
teste de egress confirme que destinos externos são inacessíveis.

## Zeek e Suricata no Windows

O Suricata 8.0.7 está instalado em `C:\Program Files\Suricata`. O adaptador inclui
automaticamente o diretório Npcap no `PATH` do subprocesso. O Zeek usa a imagem
oficial `zeek/zeek:lts`; a instalação nativa Windows é experimental. Neste host,
o Docker Desktop não conseguiu iniciar, portanto a imagem Zeek ainda não pôde
ser baixada. Após corrigir Docker/WSL:

```powershell
docker pull zeek/zeek:lts
$env:PCAP_ZEEK_BINARY = "docker://zeek/zeek:lts"
```

## Relatório final

Os endpoints produzem JSON, HTML e PDF. A versão 1.4 inclui versões dos
analisadores, conclusão, próximos passos, limitações e SHA-256 do JSON canônico.
O hash detecta alterações acidentais ou deliberadas; não substitui uma assinatura
digital com chave privada.
