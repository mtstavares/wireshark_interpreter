# Arquitetura

## Visão geral

```text
┌──────────┐   ┌────────────┐   ┌────────────────────────┐
│ Frontend │──▶│ API        │──▶│ Fila / orquestrador    │
└──────────┘   └─────┬──────┘   └───────────┬────────────┘
                     │                      │
               PostgreSQL             Worker isolado
                                            │
                              ┌─────────────┼─────────────┐
                              ▼             ▼             ▼
                            Zeek        Suricata        TShark
                              └─────────────┬─────────────┘
                                            ▼
                               Normalização e detectores
                                            │
                                            │
                                            ▼
                               Relatório determinístico
```

## Componentes

### API

Responsável por autenticação futura, upload, validação superficial, criação do job, consulta de estado e acesso aos resultados. Não processa PCAP diretamente.

### Armazenamento de evidências

- Arquivo original imutável durante a análise.
- Nome interno gerado pela aplicação; o nome enviado é apenas metadado.
- SHA-256 calculado no ingresso.
- Diretório exclusivo por job.
- Política de expiração configurável.

### Worker

Executa analisadores em subprocessos ou containers sem privilégios, com limites de CPU, memória, tempo, arquivos e rede. A análise offline não necessita de saída para a internet.

### Adaptadores

- `ZeekAdapter`: conexões e semântica de protocolos.
- `SuricataAdapter`: alertas, anomalias e metadados IDS.
- `TsharkAdapter`: metadados da captura e detalhes pontuais.

Cada adaptador converte sua saída para modelos internos; nenhum componente posterior depende diretamente do formato nativo da ferramenta.

### Motor de detecção

Detectores são funções puras sempre que possível:

```text
eventos normalizados + configuração -> findings + evidências
```

### Capturas grandes

- Pacotes do TShark sao agregados por chave canonica de fluxo em tempo linear.
- Cada fluxo mantem no maximo 100 referencias de pacote; os eventos individuais
  continuam auditaveis no banco.
- Fluxos e eventos sao gravados no SQLite em lotes de 2.000 registros.
- O SQLite opera em WAL, com espera de 30 segundos para contencao de escrita.
- A normalizacao tem timeout configuravel por
  `PCAP_NORMALIZATION_TIMEOUT_SECONDS` (900 segundos por padrao).
- Ao iniciar, a aplicacao converte jobs `queued` ou `running` abandonados em
  `failed`, registrando que houve uma reinicializacao.

Um detector não chama LLM e não modifica dados de outro detector.

### Relatórios

O relatório canônico é montado sob demanda a partir da captura, da análise, do inventário e dos findings persistidos. JSON e HTML usam o mesmo modelo versionado; por isso, não recalculam severidade nem produzem conclusões diferentes. O HTML é autocontido, não executa JavaScript e escapa todo conteúdo originado das ferramentas ou da captura.

A versão 1.2 inclui a seção **O que aconteceu**. Cada atividade usa linguagem
direta e permanece ligada ao finding, origem, destino, horário, confiança,
classificação e referências de evidência. Identificadores de usuário podem ser
mostrados quando observados, mas senhas, tokens e outros segredos nunca são
incluídos no relatório.

O campo `generated_at` deriva do término da análise, em vez do horário da requisição. Assim, duas exportações dos mesmos dados e da mesma versão do contrato permanecem idênticas.

### Enriquecimento

Consultas externas são opcionais, possuem cache, timeout, identificação de fonte e timestamp. A ausência de enriquecimento nunca impede o relatório base.

Na Sprint 7, o comportamento padrão permanece offline. Um catálogo embutido liga
detectores a referências CWE e MITRE ATT&CK; identificadores CVE citados por uma
assinatura são preservados como contexto não confirmado. CPE e extensões podem
ser fornecidos por um catálogo JSON revisado pelo operador. Reputação também é
injetada por arquivo JSON configurável, com validade e cache persistente entre
análises. Cada registro guarda provider, URL, confiança, horário, expiração,
cache hit e influência `context_only`.

O contexto de ativos é derivado do inventário e pode ser complementado com
nome, papel, proprietário, criticidade, labels e redes em allowlist. Allowlist
expressa contexto conhecido; não elimina findings nem autoriza testes ativos.

### LLM

Componente futuro e fora do MVP. Quando implementado, receberá somente um pacote de evidências reduzido e poderá agrupar, correlacionar, explicar e sugerir mitigação. Não criará fatos nem executará ações diretamente.

## Estados do job

```text
received -> validated -> extracting -> detecting -> enriching
         -> correlating -> reporting -> completed
```

Qualquer fase pode terminar em `failed`. A fase `correlating` só será habilitada após a futura integração da LLM; até lá o fluxo segue de `enriching` para `reporting`.

## Modelo mínimo de domínio

- `Capture`: arquivo, hash, tamanho, duração e contagem de pacotes.
- `Asset`: IP/MAC, papel inferido e indicadores de contexto.
- `Flow`: tupla de rede, horários, protocolo, volume e identificadores de origem.
- `Event`: fato normalizado emitido por uma fonte.
- `Evidence`: referência imutável a evento, fluxo ou pacote.
- `Finding`: interpretação determinística de uma ou mais evidências.
- `Enrichment`: dado externo com fonte e validade.
- `Analysis`: execução, versões, estado, métricas e erros.
- `Report`: visão renderizada e versão do contrato.

## Correlação

O identificador interno de fluxo é estável dentro de uma análise. IDs nativos do Zeek e Suricata são preservados para auditoria. Quando disponível, Community ID pode auxiliar correlação, mas não substitui a tupla, direção e janela temporal.

## Validação ativa

A validação ativa é um subsistema separado e desabilitado por padrão. Seus controles obrigatórios são:

- Declaração de autorização e escopo.
- Allowlist exata de destino e porta.
- Ferramentas e templates permitidos por política.
- Ausência de comandos arbitrários fornecidos pela LLM.
- Testes não destrutivos, com timeout e rate limit.
- Container sem privilégios e com egress restrito.
- Aprovação humana para qualquer operação sensível.
- Log imutável de ferramenta, argumentos, operador e resultado.

## Implantação inicial

Docker Compose com API, worker, banco e frontend. Redis só será adicionado quando a fila em banco ou processo local deixar de atender aos requisitos medidos.
