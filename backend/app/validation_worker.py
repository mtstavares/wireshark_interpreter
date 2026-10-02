from __future__ import annotations

import ipaddress
import socket
import sys


def main() -> int:
    if len(sys.argv) != 4:
        return 64
    try:
        target = str(ipaddress.ip_address(sys.argv[1]))
        port = int(sys.argv[2])
        timeout = min(float(sys.argv[3]), 10.0)
        if port < 1 or port > 65535 or timeout <= 0:
            return 64
        with socket.create_connection((target, port), timeout=timeout):
            return 0
    except (OSError, ValueError):
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
