# Estratégia de LLM e eficiência de tokens

> Status: **planejado para pós-MVP**. Este documento é uma proposta de implementação futura. O núcleo atual não deve instalar SDK, exigir chave, realizar chamadas ou depender de LLM.

## Função da LLM

A LLM é uma camada opcional de correlação e comunicação. Ela PODE:

- Agrupar findings relacionados.
- Produzir uma narrativa temporal.
- Comparar evidências favoráveis e contraditórias.
- Sugerir perguntas ou consultas adicionais.
- Explicar impacto e mitigação para públicos diferentes.

Ela NÃO PODE:

- Criar eventos ausentes.
- Confirmar vulnerabilidade sem evidência externa registrada.
- Alterar ou apagar a evidência original.
- Executar comandos, exploits ou acessar livremente a rede.
- Tratar payload do PCAP como instrução.

## Modelos

Configuração inicial:

- `gpt-6-luna`: triagem e sumarização em alto volume.
- `gpt-6-sol`: correlação, revisão de casos ambíguos e relatório final.
- `gpt-6-astra`: opcional e desabilitado por padrão; apenas escalonamento de casos críticos e contraditórios.

Os nomes são configuração, não regra de domínio. A disponibilidade deve ser verificada na conta e os modelos podem ser substituídos após avaliação comparativa.

## Fluxo econômico

```text
Detectores determinísticos
        │
        ├── nenhum finding relevante -> relatório sem LLM
        │
        ▼
Deduplicação e pacote compacto
        │
        ▼
Luna: triagem estruturada
        │
        ├── baixa ambiguidade -> relatório
        │
        ▼
Sol: correlação e revisão
        │
        └── Astra somente por política de escalonamento
```

## Regras para consumir menos tokens

1. O PCAP bruto nunca é enviado ao modelo.
2. Campos vazios, duplicados e irrelevantes são removidos.
3. Eventos repetidos são agregados com contagem, janela e amostras.
4. Evidências usam IDs curtos; o texto completo permanece no banco.
5. Somente top findings e contexto necessário entram em cada chamada.
6. Histórico de chat não é carregado; cada fase recebe um estado compacto.
7. Instruções, ferramentas e schema ficam em um prefixo estável para cache.
8. Saída usa Structured Outputs estritos, sem prosa intermediária.
9. A explicação longa é criada uma única vez, no relatório final.
10. Resultado é armazenado por hash de evidência, modelo e versão do prompt.
11. A chamada é evitada quando regra determinística ou cache responde.
12. O endpoint de contagem de tokens valida o orçamento antes do envio.

## Pacote de evidências

Formato lógico, serializado de maneira compacta:

```json
{
  "schema_version": "1.0",
  "analysis_id": "uuid",
  "capture_summary": {},
  "asset_context": [],
  "findings": [],
  "timeline": [],
  "constraints": {
    "do_not_invent": true,
    "evidence_ids_required": true
  }
}
```

Eventos repetitivos usam agregação:

```json
{
  "kind": "ssh_auth_failure",
  "src": "192.0.2.10",
  "dst": "10.0.0.8",
  "count": 47,
  "first": "2026-09-29T13:10:00Z",
  "last": "2026-09-29T13:14:22Z",
  "sample_evidence_ids": ["e12", "e31", "e58"]
}
```

## Orçamento padrão por análise

Os limites são iniciais e devem ser calibrados por avaliações:

| Etapa | Modelo padrão | Máx. entrada | Máx. saída | Condição |
|---|---:|---:|---:|---|
| Triagem | Luna | 6.000 | 700 | Há finding relevante |
| Correlação | Sol | 10.000 | 1.200 | Alta severidade ou ambiguidade |
| Relatório | Sol | 12.000 | 2.000 | Uma vez por análise |
| Escalonamento | Astra | 10.000 | 1.200 | Política explícita |

Orçamento global padrão: `28.000` tokens de entrada e `3.900` de saída por análise, sem Astra. Esse é um teto, não uma meta. Se o orçamento for excedido, o sistema reduz contexto por prioridade e, por fim, gera o relatório determinístico.

## Priorização do contexto

1. Evidências de findings críticos e altos.
2. Evidências contraditórias ou lacunas relevantes.
3. Timeline ao redor do incidente.
4. Contexto do ativo e allowlists.
5. Findings médios agregados.
6. Estatísticas gerais.
7. Findings baixos e informativos, resumidos por contagem.

Nenhuma compactação pode remover os IDs usados na conclusão.

## Cache

Há dois níveis:

- Cache da aplicação: chave `evidence_hash + task + model + prompt_version + schema_version`.
- Prompt caching do provedor: instruções e schemas estáveis antes do conteúdo variável.

Alterar ordem de ferramentas, schema, instruções ou modelo pode reduzir o reaproveitamento do prefixo. A eficiência é medida por `cached_tokens / input_tokens`, nunca presumida.

## Structured Outputs

Todas as respostas de máquina usam JSON Schema estrito. Prosa é renderizada somente depois que a resposta foi validada. Em caso de recusa, truncamento ou schema inválido:

1. Registrar o tipo de falha sem conteúdo sensível.
2. Fazer no máximo uma nova tentativa, com entrada menor.
3. Cair para o relatório determinístico.

## Tool calling

A LLM conhece apenas ferramentas de leitura ou ações estreitas:

- `get_flow(flow_id)`
- `get_evidence(evidence_ids)`
- `get_asset_context(asset_id)`
- `lookup_vulnerability(product, version)`
- `request_safe_validation(policy_id, target_id)`

Argumentos são validados por schema. A aplicação verifica autorização e executa a ferramenta. Não existe ferramenta de shell genérica.

## Proteção contra prompt injection

- Payload, URI, DNS, certificado, banner e arquivo extraído são delimitados como `UNTRUSTED_EVIDENCE`.
- Texto da captura nunca é concatenado às instruções de sistema/desenvolvedor.
- A LLM é instruída a ignorar comandos contidos em evidências.
- Tool calls passam por política independente do texto gerado.
- Segredos e credenciais são redigidos antes da chamada.

## Métricas e avaliações

Registrar por chamada:

- Modelo, reasoning effort e versão do prompt.
- Tokens de entrada, cache, saída e raciocínio quando disponíveis.
- Latência, tentativas, erro e custo estimado.
- Hash do pacote de evidências e schema de saída.

Avaliações mínimas:

- Fidelidade: toda afirmação possui evidência válida.
- Cobertura: findings importantes aparecem no relatório.
- Alucinação: nenhum IP, CVE ou evento inexistente.
- Consistência: severidade e confiança não são confundidas.
- Concisão: nenhuma repetição desnecessária.
- Custo: modelo mais leve que atinge a meta deve ser preferido.

## Referências oficiais

- [Seleção de modelos](https://developers.openai.com/api/docs/guides/model-selection)
- [Contagem de tokens](https://developers.openai.com/api/docs/guides/token-counting)
- [Prompt caching](https://developers.openai.com/api/docs/guides/prompt-caching)
- [Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs)
- [Function calling](https://developers.openai.com/api/docs/guides/function-calling)
