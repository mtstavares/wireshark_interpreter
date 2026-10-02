# Teste manual — Sprint 10

## 1. Iniciar sem política de autorização

```powershell
$env:PCAP_TSHARK_BINARY = "C:\Program Files\Wireshark\tshark.exe"
$env:PCAP_SURICATA_BINARY = "C:\Program Files\Suricata\suricata.exe"
Remove-Item Env:PCAP_CREDENTIAL_POLICY_FILE -ErrorAction SilentlyContinue
..\.venv\Scripts\uvicorn.exe backend.app.main:app --reload
```

Envie pela interface um PCAP autorizado que contenha autenticação sem TLS em
FTP, POP3, IMAP, SMTP, HTTP Basic ou Telnet. Uma análise criada antes desta sprint
não será recalculada; execute uma nova análise.

No finding, confirme conforme o protocolo:

- FTP `230`, POP3 `+OK`, IMAP `OK` ou SMTP `235`: sucesso observado;
- respostas negativas explícitas: tentativa malsucedida;
- HTTP 2xx/3xx: possível aceitação, sem afirmar sucesso;
- troca sem resposta conclusiva: resultado desconhecido;
- usuário e senha aparecem por inteiro no resumo e nos detalhes do evento.

Para conferir no Wireshark, use o número indicado pela evidência ou filtre:

```text
ftp.request.command == "USER" || ftp.request.command == "PASS" || ftp.response.code == 230
```

## 2. Testar autorização local

Copie e ajuste `samples/credentials/policy.example.json`. Depois reinicie:

```powershell
$env:PCAP_CREDENTIAL_POLICY_FILE = "$PWD\samples\credentials\policy.example.json"
..\.venv\Scripts\uvicorn.exe backend.app.main:app --reload
```

Com `default` igual a `deny`, um login bem-sucedido que não corresponda a uma
regra deve gerar **Autenticação não autorizada em texto claro**, severidade
crítica. Uma regra corresponde a destino, serviço, usuário e, quando presente,
rede de origem. Sem arquivo de política, a aplicação nunca presume que o acesso
foi autorizado ou não autorizado.

## 3. Limites esperados

- SSH e tráfego protegido por TLS não revelam usuário/senha para este recurso.
- Capturas truncadas podem produzir resultado desconhecido.
- Telnet depende de prompts reconhecíveis (`login:`, `username:`, `password:`) e
  mensagens explícitas de sucesso ou falha.
- O PCAP, `.data/app.db`, JSON, HTML e PDF agora podem conter credenciais reais.
  Não publique esses artefatos e habilite `PCAP_AUTH_USERNAME` e
  `PCAP_AUTH_PASSWORD` ao expor a aplicação em rede.
