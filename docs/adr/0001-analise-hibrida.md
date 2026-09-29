# ADR 0001 — Análise híbrida determinística e assistida por LLM

- Status: aceito para implementação futura
- Data: 2026-09-29

## Contexto

LLMs são úteis para correlação e explicação, mas podem produzir afirmações sem evidência e têm custo variável. Analisadores de rede e regras determinísticas são mais reproduzíveis, porém menos flexíveis na construção de narrativas.

## Decisão

Zeek, Suricata, TShark e detectores próprios produzem os fatos e findings base. O MVP e a fase de consolidação não incluem LLM. Depois da consolidação, a LLM poderá receber somente evidências selecionadas e atuar como camada opcional de correlação e apresentação. O relatório base sempre existe sem LLM.

## Consequências

- Resultados principais permanecem auditáveis e reproduzíveis.
- Indisponibilidade ou limite de custo da LLM não interrompe a análise.
- A aplicação precisa manter contratos claros de evidência e avaliações específicas para a camada generativa.
- Há mais trabalho de normalização, compensado por menor acoplamento a fornecedores e modelos.
