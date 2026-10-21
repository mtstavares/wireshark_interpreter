# Sprint 12 — qualidade e precisão das detecções

## Entregas

- Regressão ponta a ponta do PCAP abrangente usando o TShark real.
- Expectativas versionadas por detector, título e quantidade.
- Métricas TP, FP, FN, precisão e recall para cada família de regras.
- Correlação entre requisição e resposta HTTP pelo `tcp.stream`.
- Corpo HTTP textual limitado a 300 caracteres como evidência explicativa.
- Classificação conservadora entre tentativa, possível sucesso e rejeição.
- Protocolos inseguros exigem protocolo realmente identificado; um SYN isolado em porta conhecida
  não é mais suficiente.
- Página **Cobertura** na interface e endpoint `GET /api/v1/quality/coverage`.
- Regras identificadas pela versão `1.2.0`.

## Validação automática

Com o servidor parado, execute:

```powershell
.\.venv\Scripts\python.exe -m scripts.validate_comprehensive_corpus `
  --output reports\quality-sprint-12.json
```

O comando opera em modo estrito e retorna código diferente de zero se houver falso positivo ou
falso negativo. O baseline esperado é:

```text
TP: 23
FP: 0
FN: 0
Precisão: 100%
Recall: 100%
```

Essas métricas medem somente o corpus sintético versionado e não representam desempenho universal
contra todo tráfego de rede.

## Teste pela aplicação

1. Inicie a aplicação e abra `http://127.0.0.1:8000`.
2. Entre em **Cobertura** e confirme a versão `1.2.0`, TP 23, FP 0 e FN 0.
3. Envie `samples/corpus/comprehensive-attacks.pcap` e inicie uma nova análise.
4. Abra o finding de SQL injection.
5. Confirme que o resumo contém:
   - o payload `admin' OR '1'='1'--`;
   - a resposta HTTP 200;
   - o conteúdo `Welcome admin`;
   - a expressão “possível exploração bem-sucedida”;
   - a orientação de confirmação nos logs da aplicação.
6. Confira XSS, path traversal e injeção de comandos. Eles recebem HTTP 200, mas o corpo genérico
   não é tratado como comprovação de sucesso.
7. Confirme que o scan contra `10.10.0.20` não cria findings falsos de FTP, Telnet ou SMTP apenas
   por ter tocado as portas 21, 23 e 25.

## API de cobertura

```text
GET http://127.0.0.1:8000/api/v1/quality/coverage
```

A resposta informa o hash da captura, versão das regras, data do baseline, métricas por detector e
limitações. A documentação interativa está disponível em `http://127.0.0.1:8000/docs`.

## Limitações

- HTTP 200 sem indicador contextual continua sendo apenas resposta observada, não sucesso.
- A frase `Welcome admin` eleva a conclusão para possível sucesso, não confirmação definitiva.
- SSH permanece criptografado e não fornece senha ou resultado explícito de autenticação.
- Novas regras ou alterações no corpus exigem atualização consciente das expectativas e do baseline.
