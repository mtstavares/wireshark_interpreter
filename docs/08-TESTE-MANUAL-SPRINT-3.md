# Teste manual — Sprint 3

## Pré-requisito

Para produzir fluxos reais, pelo menos um analisador deve estar instalado. No Windows, o caminho mais simples é instalar o Wireshark com TShark e configurar:

```powershell
$env:PCAP_TSHARK_BINARY = "C:\Program Files\Wireshark\tshark.exe"
.\.venv\Scripts\uvicorn.exe backend.app.main:app --reload
```

## Procedimento

1. Abra `http://127.0.0.1:8000/docs`.
2. Envie um PCAP em `POST /api/v1/captures`.
3. Crie o job em `POST /api/v1/captures/{capture_id}/analyses`.
4. Consulte `GET /api/v1/analyses/{analysis_id}` até sair de `queued` ou `running`.
5. Confirme que `normalization.status` é `completed`.
6. Consulte os novos endpoints:

```text
GET /api/v1/analyses/{analysis_id}/flows
GET /api/v1/analyses/{analysis_id}/events
GET /api/v1/analyses/{analysis_id}/inventory
```

## Resultado esperado

- `flows` apresenta endereços, portas, transporte, aplicação, volume, pacotes e referências de evidência.
- `events` apresenta uma timeline comum, independentemente da ferramenta de origem.
- `inventory` apresenta hosts observados e serviços de destino.
- Quando duas ferramentas descrevem a mesma comunicação, `sources` contém ambas sem duplicar o volume.

O PCAP vazio criado pelo script da Sprint 2 produzirá zero fluxos. Para este teste, use uma captura que contenha tráfego autorizado, mesmo que seja apenas uma consulta DNS criada em laboratório.

## Verificação automatizada

```powershell
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\pyright.exe
.\.venv\Scripts\pytest.exe --cov=backend.app --cov-report=term-missing
```

