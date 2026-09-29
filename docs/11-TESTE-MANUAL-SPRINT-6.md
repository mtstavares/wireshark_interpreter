# Teste manual da Sprint 6

Este roteiro valida a interface e o fluxo completo usando o arquivo
`teste.pcapng` da raiz do projeto. Nenhuma LLM ou conexão de reputação externa é
utilizada.

## 1. Preparar e iniciar

No PowerShell, a partir da raiz:

```powershell
$env:PCAP_TSHARK_BINARY = "C:\Program Files\Wireshark\tshark.exe"
Set-Location frontend
npm.cmd install
npm.cmd run build
Set-Location ..
.\.venv\Scripts\uvicorn.exe backend.app.main:app --reload
```

Abra `http://127.0.0.1:8000/`. O dashboard deve carregar sem retornar `404` e
exibir as capturas e análises já registradas.

## 2. Enviar a captura

1. Clique em **Nova análise**.
2. Arraste `teste.pcapng` para a área de upload, ou selecione-o pelo explorador.
3. Confirme o nome e o tamanho do arquivo.
4. Clique em **Enviar e analisar**.

Resultado esperado:

- o progresso do upload é exibido;
- a aplicação abre automaticamente a investigação criada;
- os estados de extração, normalização e detecção são atualizados;
- TShark aparece como concluído;
- sem Zeek e Suricata instalados, o resultado fica **Com avisos**, sem impedir a
  investigação.

## 3. Conferir o resultado de referência

Com a versão atual do `teste.pcapng`, a tela **Resumo** deve apresentar:

- 157 eventos;
- 32 fluxos;
- 19 hosts;
- 17 serviços;
- 1 finding de severidade média.

Na aba **Findings**, abra **Uso observado de versão legada do SNMP**. Confirme:

- origem `10.44.44.21`;
- destino `10.44.44.100:161`;
- confiança de 99%;
- quatro requisições SNMPv1/v2c observadas;
- evidências produzidas pelo TShark;
- filtro copiável do Wireshark;
- recomendações de migração para SNMPv3, restrição de UDP/161 e isolamento da
  rede de gerenciamento.

## 4. Exercitar a investigação

Na aba **Rede**:

1. busque por `snmp` e confirme o serviço UDP/161;
2. busque por `10.44.44.100` e confira o host e o fluxo;
3. confirme que não existe host com IP vazio;
4. confirme que endereços privados, link-local e multicast não aparecem como
   públicos.

Na aba **Timeline**, localize os pacotes SNMP 47–50 e 96–99 e o finding no
horário correspondente.

Na aba **Relatório**:

1. confirme que a prévia HTML é carregada;
2. abra ou baixe o HTML;
3. baixe o JSON;
4. confira se ambos apresentam o mesmo finding e as mesmas limitações.

## 5. Validar filtros e erros

- Em **Findings**, filtre por severidade média e pesquise por `SNMP`.
- Troque o filtro para crítica e confirme o estado vazio.
- Na tela de upload, tente selecionar um arquivo que não seja `.pcap` ou
  `.pcapng`; o envio deve ser recusado antes da análise.
- Atualize diretamente uma rota interna da aplicação. Como a interface usa hash
  routing, a página deve continuar abrindo normalmente.

## 6. Verificação automatizada complementar

```powershell
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\pyright.exe
.\.venv\Scripts\pytest.exe --cov=backend.app --cov-report=term-missing
Set-Location frontend
npm.cmd run lint
npm.cmd run test
npm.cmd run build
```

O teste manual é aprovado quando upload, acompanhamento, investigação e exportação
funcionam pelo navegador, e todas as verificações automatizadas terminam sem erro.
