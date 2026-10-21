# Wireshark Interpreter

Aplicação criada a partir de atividades de estudo em laboratórios da DESEC Security, com o objetivo de facilitar a análise de capturas de rede nos formatos PCAP e PCAPNG.

A ferramenta interpreta o tráfego capturado, organiza as comunicações e identifica possíveis eventos de segurança, como varreduras de portas, tentativas de força bruta, autenticações bem-sucedidas, credenciais transmitidas em protocolos sem criptografia e ataques contra aplicações web, incluindo SQL injection, XSS, path traversal e command injection.

Ao final da análise, a aplicação gera um relatório de fácil leitura com as evidências encontradas, uma explicação do que aconteceu e recomendações de mitigação. O projeto foi desenvolvido para apoiar estudos, investigações em laboratório e a prática de análise de tráfego e resposta a incidentes.

## Tecnologias utilizadas

- Python 3.12
- FastAPI
- Pydantic
- SQLAlchemy e Alembic
- SQLite
- TShark/Wireshark
- Zeek e Suricata
- React
- TypeScript
- Vite
- TanStack Query
- Pytest, Ruff, Pyright e Vitest
- Docker e Docker Compose
