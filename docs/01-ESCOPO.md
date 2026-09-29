# Escopo do produto

## Problema

PCAPs contêm evidências valiosas, mas exigem conhecimento técnico e correlação manual. O produto deve reduzir esse trabalho sem esconder a origem das conclusões.

## Público-alvo

- Analistas SOC e resposta a incidentes em treinamento.
- Estudantes e profissionais de segurança.
- Equipes que precisam de uma primeira triagem de uma captura autorizada.
- Recrutadores avaliando um projeto prático de cibersegurança.

## Casos de uso do MVP

1. Enviar um arquivo `.pcap` ou `.pcapng`.
2. Validar tipo, tamanho, integridade e metadados da captura.
3. Extrair logs de rede com Zeek e alertas com Suricata.
4. Normalizar hosts, fluxos, protocolos e alertas.
5. Detectar padrões básicos de ataque ou exposição.
6. Exibir evidências e filtros reproduzíveis do Wireshark.
7. Gerar relatório JSON e HTML; PDF entra após estabilizar o HTML.

## Detecções iniciais

- Varredura horizontal e vertical de portas.
- Força bruta e password spraying quando o protocolo fornece evidência suficiente.
- Falhas seguidas de possível autenticação bem-sucedida.
- Credenciais ou autenticação em protocolo sem criptografia.
- Consultas DNS anômalas, possíveis túneis e domínios de alta entropia.
- Beaconing e conexões periódicas.
- Alertas IDS e tentativas de exploração reconhecidas pelo Suricata.
- Transferências de arquivos e executáveis observáveis.
- Serviços, banners e versões potencialmente associados a CVEs.
- Comunicação com indicadores conhecidos, quando o enriquecimento estiver habilitado.
- Volume ou destino compatível com possível exfiltração.

## Entregáveis do MVP

- API de upload e consulta do andamento.
- Worker de análise offline.
- Inventário de hosts, serviços, protocolos e conversações.
- Timeline e lista de findings.
- Relatório com resumo executivo, detalhes técnicos, evidências, limitações e mitigações.
- Conjunto pequeno de PCAPs benignos e maliciosos para regressão.
- Métricas de tempo, erros, tokens e custo estimado.

## Fora do escopo inicial

- Captura ao vivo de interfaces.
- SIEM completo ou retenção de tráfego em escala empresarial.
- EDR, análise de memória ou perícia de disco.
- Quebra ou interceptação de TLS.
- Exploração automática de sistemas observados no PCAP.
- Afirmação de vulnerabilidade apenas com base em banner ou versão aparente.
- Treinamento ou fine-tuning de modelo no MVP.
- Uso da LLM para examinar todos os pacotes individualmente.
- Qualquer SDK, chave, chamada ou dependência operacional de LLM.

## Limitações declaradas

- Capturas podem estar truncadas, incompletas ou sem o início de uma sessão.
- TLS pode ocultar conteúdo e resultados de autenticação.
- Um código HTTP isolado não comprova sucesso de login.
- Um IP reputado pode pertencer a infraestrutura compartilhada.
- Uma versão identificada pode ter backports de segurança.
- O PCAP representa um momento passado; o estado atual do alvo pode ser diferente.

## Critérios de sucesso

- Todo finding possui pelo menos uma evidência rastreável.
- O relatório não transforma inferência em fato.
- A mesma entrada e versões de regras produzem resultados determinísticos.
- O MVP funciona integralmente sem LLM e não exige chave de provedor.
- Nenhum teste ativo ocorre sem autorização e allowlist explícitas.

## Definição de pronto do MVP

O MVP estará pronto quando uma captura de teste puder ser enviada, analisada de ponta a ponta e resultar em relatório reproduzível, contendo ao menos inventário de rede, cinco famílias de detecção, evidências, severidade, confiança, limitações e recomendações.

## Decisão sobre LLM

A integração foi adiada até que ingestão, análise determinística, interface, relatórios, enriquecimento e testes estejam consolidados. A documentação de LLM permanece como proposta futura e não compõe a definição de pronto do MVP.
