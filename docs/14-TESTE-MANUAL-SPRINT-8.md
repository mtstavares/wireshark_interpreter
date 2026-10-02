# Teste manual — Sprint 8

Este roteiro valida primeiro o bloqueio seguro. Só faça a etapa ativa em um
laboratório próprio ou formalmente autorizado.

## 1. Confirmar o comportamento padrão

Inicie a aplicação sem definir `PCAP_VALIDATION_POLICY_FILE`, envie um PCAP e
execute a análise normalmente. Abra a análise e acesse **Validação**.

Escolha um finding que possua IP e porta de destino, informe seu nome e uma
referência de escopo, marque a confirmação e clique em **Criar dry-run**.

Resultado esperado:

- nenhum pacote novo é enviado;
- o registro aparece como `Bloqueada`;
- a razão informa que a porta, o IP ou a validação ativa não está permitido;
- não existe botão para aprovar uma validação bloqueada.

## 2. Executar os testes automatizados de segurança

No PowerShell, a partir da raiz:

```powershell
.\.venv\Scripts\pytest.exe -q tests\unit\test_validation.py
.\.venv\Scripts\pytest.exe -q tests\integration\test_captures_api.py -k safe_validation
```

O teste de integração usa uma conexão simulada. Ele comprova que o dry-run e a
frase errada não conectam, que o alvo exato é preservado e que execução e revisão
entram na auditoria e no relatório.

## 3. Validação ativa opcional em laboratório

Crie uma cópia local da política de exemplo e altere somente:

- `active_enabled` para `true`;
- `allowed_networks` para o menor CIDR que contém o alvo autorizado;
- `allowed_ports` para a porta exata observada no finding.

Não use `0.0.0.0/0`. Mantenha `allow_public_targets` como `false`. Depois defina:

```powershell
$env:PCAP_VALIDATION_POLICY_FILE = "C:\caminho\policy.local.json"
.\.venv\Scripts\uvicorn.exe backend.app.main:app --reload
```

Na tela **Validação**:

1. Crie o dry-run e confira alvo, porta, escopo e razão da política.
2. Informe um aprovador diferente quando seu processo exigir segregação.
3. Digite exatamente `AUTORIZADO` e execute.
4. Classifique como `Confirmado`, `Falso positivo` ou `Inconclusivo`, sempre com justificativa.
5. Abra **Relatório** e confirme a seção **Validações seguras** e sua trilha.

Resultado esperado: somente uma tentativa de conexão TCP é feita, sem dados de
aplicação. `reachable` significa apenas que a porta aceitou a conexão;
`not_reachable` não elimina a evidência histórica presente no PCAP.
