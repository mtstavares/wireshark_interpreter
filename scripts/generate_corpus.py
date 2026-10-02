from __future__ import annotations

import socket
import struct
from pathlib import Path

OUTPUT = Path("samples/corpus")


def _ethernet_ipv4_tcp(src: str, dst: str, src_port: int, dst_port: int) -> bytes:
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    source = socket.inet_aton(src)
    destination = socket.inet_aton(dst)
    tcp = struct.pack("!HHLLBBHHH", src_port, dst_port, 0, 0, 5 << 4, 0x02, 64240, 0, 0)
    total_length = 20 + len(tcp)
    ip_without_checksum = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total_length, 1, 0, 64, 6, 0, source, destination
    )
    checksum = _checksum(ip_without_checksum)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        0,
        64,
        6,
        checksum,
        source,
        destination,
    )
    return ethernet + ip_header + tcp


def _checksum(payload: bytes) -> int:
    if len(payload) % 2:
        payload += b"\x00"
    words = struct.unpack(f"!{len(payload) // 2}H", payload)
    total = sum(words)
    total = (total & 0xFFFF) + (total >> 16)
    total += total >> 16
    return (~total) & 0xFFFF


def _write(name: str, packets: list[bytes]) -> None:
    content = bytearray(bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000"))
    for index, packet in enumerate(packets):
        content.extend(struct.pack("<IIII", 1_700_000_000 + index, 0, len(packet), len(packet)))
        content.extend(packet)
    (OUTPUT / name).write_bytes(content)


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    _write(
        "benign-https.pcap",
        [_ethernet_ipv4_tcp("10.0.0.10", "10.0.0.20", 50_000 + i, 443) for i in range(5)],
    )
    _write(
        "malicious-horizontal-scan.pcap",
        [
            _ethernet_ipv4_tcp("10.0.0.5", f"10.0.1.{i}", 51_000 + i, 445)
            for i in range(1, 11)
        ],
    )
    _write(
        "malicious-vertical-scan.pcap",
        [
            _ethernet_ipv4_tcp("10.0.0.5", "10.0.0.20", 52_000 + i, port)
            for i, port in enumerate(range(20, 35))
        ],
    )
    _write(
        "malicious-telnet.pcap",
        [_ethernet_ipv4_tcp("10.0.0.10", "10.0.0.20", 53_000, 23)],
    )


if __name__ == "__main__":
    main()
