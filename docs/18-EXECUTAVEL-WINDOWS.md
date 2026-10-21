# Executável Windows

## Uso

Execute com dois cliques:

```text
release\PCAP-Security-Analyzer.exe
```

O inicializador:

1. cria o diretório `%LOCALAPPDATA%\PCAP Security Analyzer`;
2. localiza TShark e Suricata automaticamente;
3. aplica as migrations do banco SQLite;
4. inicia o servidor somente em `127.0.0.1:8000`;
5. abre `http://127.0.0.1:8000` no navegador padrão.

Para encerrar, pressione `Ctrl+C` ou feche a janela do servidor. Se uma instância
já estiver ativa, uma nova execução apenas abre a interface existente. Se outro
programa estiver ocupando a porta 8000, o inicializador apresenta uma mensagem e
não tenta encerrar esse programa.

O executável não exige Python, Node.js, ambiente virtual ou configuração manual.
Wireshark/TShark e Suricata continuam opcionais para iniciar a interface, porém
são necessários para a cobertura correspondente de análise de PCAP.

## Dados persistentes

Capturas, banco e artefatos são gravados fora do executável:

```text
%LOCALAPPDATA%\PCAP Security Analyzer
```

Esse diretório pode conter PCAPs e credenciais observadas em texto claro. Não o
publique nem compartilhe sem revisar o conteúdo.

## Build reproduzível

No diretório do projeto:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\build_windows_executable.ps1
```

O script compila o frontend, instala o PyInstaller no ambiente virtual e gera:

```text
release\PCAP-Security-Analyzer.exe
```

Teste automatizado do artefato:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\smoke_test_windows_executable.ps1
```

O smoke test usa um diretório isolado, valida `/healthz`, frontend e banco, e
encerra somente o processo iniciado por ele.

## Distribuição

O binário atual não possui assinatura Authenticode. Em outro computador, o
Windows SmartScreen pode solicitar confirmação na primeira execução. Para uma
distribuição pública, recomenda-se assinar o executável e publicar o SHA-256 junto
ao release do GitHub.
