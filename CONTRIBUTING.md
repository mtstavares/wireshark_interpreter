# Contribuição

## Fluxo

1. Crie uma branch curta (`feat/`, `fix/`, `docs/`, `test/` ou `chore/`).
2. Mantenha a alteração limitada a uma responsabilidade.
3. Adicione ou atualize testes e fixtures.
4. Execute lint, type check e testes.
5. Descreva risco, evidência de teste e impacto em contratos.

## Commits

Use Conventional Commits:

```text
feat(detectors): add horizontal scan detector
fix(parser): handle truncated dns response
docs(llm): define token budget
test(zeek): add ftp authentication fixture
```

## Regras para detectores

- Entrada e saída tipadas.
- Resultado reproduzível.
- Evidência obrigatória.
- Limiares configuráveis e documentados.
- Pelo menos um caso positivo e um benigno.
- Ausência de dependência direta da LLM.

## Regras para prompts

- Prompts ficam versionados no repositório.
- Mudanças exigem avaliação de fidelidade, alucinação, concisão e custo.
- Schemas e ferramentas permanecem estáveis quando não houver necessidade de mudança.
- Exemplos não contêm segredos nem payload real sensível.

## Decisões arquiteturais

Mudanças com impacto amplo devem criar um registro em `docs/adr/` contendo contexto, decisão, alternativas e consequências.

