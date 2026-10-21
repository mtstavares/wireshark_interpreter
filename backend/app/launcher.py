from __future__ import annotations

import json
import multiprocessing
import os
import shutil
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from contextlib import suppress
from pathlib import Path

import uvicorn

HOST = "127.0.0.1"
PORT = 8000
URL = f"http://{HOST}:{PORT}"


def main() -> int:
    multiprocessing.freeze_support()
    _configure_environment()

    if _port_in_use(HOST, PORT):
        if _is_application_running():
            print(f"A aplicação já está em execução em {URL}")
            webbrowser.open(URL)
            return 0
        return _fail(
            "A porta 8000 já está sendo usada por outro programa.\n"
            "Feche esse programa e execute novamente o PCAP Security Analyzer."
        )

    try:
        from backend.app.main import create_app

        application = create_app()
        if os.getenv("PCAP_NO_BROWSER") != "1":
            threading.Thread(target=_open_browser_when_ready, daemon=True).start()
        print("=" * 68)
        print("PCAP Security Analyzer")
        print(f"Interface: {URL}")
        print(f"Dados: {os.environ['PCAP_DATA_DIR']}")
        print(f"TShark: {os.environ['PCAP_TSHARK_BINARY']}")
        print(f"Suricata: {os.environ['PCAP_SURICATA_BINARY']}")
        print("Para encerrar, pressione Ctrl+C ou feche esta janela.")
        print("=" * 68)
        uvicorn.run(application, host=HOST, port=PORT, log_level="info")
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        return _fail(f"Não foi possível iniciar a aplicação:\n{type(exc).__name__}: {exc}")
    return 0


def _configure_environment() -> None:
    local_app_data = Path(
        os.getenv("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))
    )
    data_dir = local_app_data / "PCAP Security Analyzer"
    data_dir.mkdir(parents=True, exist_ok=True)

    os.environ["PCAP_DATA_DIR"] = str(data_dir)
    os.environ["PCAP_TSHARK_BINARY"] = _find_executable(
        "tshark.exe",
        [
            Path(os.getenv("PROGRAMFILES", r"C:\Program Files"))
            / "Wireshark"
            / "tshark.exe",
            Path(os.getenv("PROGRAMFILES(X86)", r"C:\Program Files (x86)"))
            / "Wireshark"
            / "tshark.exe",
        ],
    )
    os.environ["PCAP_SURICATA_BINARY"] = _find_executable(
        "suricata.exe",
        [
            Path(os.getenv("PROGRAMFILES", r"C:\Program Files"))
            / "Suricata"
            / "suricata.exe",
        ],
    )
    os.environ.setdefault("PCAP_ZEEK_BINARY", "zeek")


def _find_executable(name: str, candidates: list[Path]) -> str:
    discovered = shutil.which(name)
    if discovered:
        return discovered
    return str(next((path for path in candidates if path.is_file()), Path(name)))


def _port_in_use(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(0.25)
        return connection.connect_ex((host, port)) == 0


def _is_application_running() -> bool:
    try:
        with urllib.request.urlopen(f"{URL}/healthz", timeout=1) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return response.status == 200 and payload == {"status": "ok"}
    except (OSError, ValueError, urllib.error.URLError):
        return False


def _open_browser_when_ready() -> None:
    for _ in range(100):
        if _is_application_running():
            webbrowser.open(URL)
            return
        time.sleep(0.1)


def _fail(message: str) -> int:
    print(message, file=sys.stderr)
    if sys.stdin.isatty():
        with suppress(EOFError, KeyboardInterrupt):
            input("\nPressione Enter para fechar...")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
