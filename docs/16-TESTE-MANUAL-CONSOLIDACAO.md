# Teste manual — consolidação

## 1. Regressão e qualidade

```powershell
.\.venv\Scripts\pytest.exe -q
.\.venv\Scripts\python.exe -m scripts.evaluate_corpus
```

Esperado: todos os testes aprovados; corpus com TP=4, FP=1, FN=0, precisão
0,800 e recall 1,000.

## 2. Arquivo corrompido

Tente enviar um arquivo `.pcap` contendo somente os quatro bytes mágicos. A API
deve responder 422 e não deixar arquivo em `.data/captures`.

## 3. Cancelamento e limites

Envie uma captura grande, inicie a análise e clique em **Cancelar análise** antes
do término. O estado deve mudar para `Cancelada` e o subprocesso ativo deve ser
encerrado. Os limites podem ser reduzidos temporariamente para teste:

```powershell
$env:PCAP_ANALYZER_TIMEOUT_SECONDS = "5"
$env:PCAP_ANALYZER_MEMORY_LIMIT_MB = "64"
$env:PCAP_ANALYZER_CPU_LIMIT_SECONDS = "5"
```

Reinicie o Uvicorn depois de alterar as variáveis.

## 4. Retenção

```powershell
.\.venv\Scripts\python.exe -m scripts.retention --days 30
```

O comando deve mostrar `dry-run` e não remover nada. Use `--apply` somente após
backup e revisão dos caminhos apresentados.

## 5. Autenticação

```powershell
$env:PCAP_AUTH_USERNAME = "analista"
$env:PCAP_AUTH_PASSWORD = "segredo-de-teste-longo"
.\.venv\Scripts\uvicorn.exe backend.app.main:app --reload
```

Abra a interface. O navegador deve solicitar usuário e senha. `/healthz`
permanece acessível sem autenticação. Limpe as variáveis após o teste.

## 6. Relatório final

Conclua uma análise e abra **Relatório**. Verifique os downloads JSON e PDF, as
versões dos analisadores, limitações, conclusão, próximos passos e o SHA-256 de
integridade. O PDF deve abrir com `%PDF` e apresentar uma página final própria.

## 7. Suricata e Zeek

Em um novo PowerShell, confirme o caminho persistido do Suricata:

```powershell
$env:PCAP_SURICATA_BINARY
```

O esperado é `C:\Program Files\Suricata\suricata.exe`. O adaptador adiciona o
Npcap ao ambiente automaticamente. Nesta máquina, a inicialização offline do
ruleset ultrapassou 120 segundos e foi encerrada pelo limite, portanto valide a
configuração/ruleset antes de aumentar o timeout.

Para o Zeek, conclua primeiro a instalação do kernel WSL 2 e reinicie o Windows.
Depois execute:

```powershell
docker pull zeek/zeek:lts
$env:PCAP_ZEEK_BINARY = "docker://zeek/zeek:lts"
docker run --rm zeek/zeek:lts zeek --version
```

O container Zeek roda sem rede e com a captura montada somente para leitura.
