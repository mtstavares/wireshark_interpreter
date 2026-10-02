from __future__ import annotations

import json
import socket
import struct
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from backend.app.detection.detectors import default_detectors
from backend.app.domain.findings import DetectionContext
from backend.app.domain.network import NetworkFlow


@dataclass(frozen=True, slots=True)
class CorpusMetrics:
    true_positive: int
    false_positive: int
    false_negative: int

    @property
    def precision(self) -> float:
        denominator = self.true_positive + self.false_positive
        return self.true_positive / denominator if denominator else 1.0

    @property
    def recall(self) -> float:
        denominator = self.true_positive + self.false_negative
        return self.true_positive / denominator if denominator else 1.0


def evaluate_corpus(corpus_dir: Path) -> CorpusMetrics:
    manifest = cast(
        dict[str, Any], json.loads((corpus_dir / "manifest.json").read_text(encoding="utf-8"))
    )
    true_positive = false_positive = false_negative = 0
    for case in cast(list[dict[str, Any]], manifest["cases"]):
        flows = read_pcap_flows(corpus_dir / str(case["file"]))
        context = DetectionContext(analysis_id=str(case["file"]), flows=flows)
        actual = {
            finding.category
            for detector in default_detectors()
            for finding in detector.detect(context)
        }
        expected = set(cast(list[str], case["expected_categories"]))
        true_positive += len(actual & expected)
        false_positive += len(actual - expected)
        false_negative += len(expected - actual)
    return CorpusMetrics(true_positive, false_positive, false_negative)


def read_pcap_flows(path: Path) -> list[NetworkFlow]:
    payload = path.read_bytes()
    if payload[:4] != bytes.fromhex("d4c3b2a1"):
        raise ValueError("Corpus reader accepts little-endian Ethernet PCAP only")
    offset = 24
    flows: list[NetworkFlow] = []
    index = 0
    while offset + 16 <= len(payload):
        seconds, micros, included_length, _ = struct.unpack_from("<IIII", payload, offset)
        offset += 16
        packet = payload[offset : offset + included_length]
        offset += included_length
        if len(packet) < 54 or packet[12:14] != b"\x08\x00" or packet[23] != 6:
            continue
        index += 1
        ip_header_length = (packet[14] & 0x0F) * 4
        transport_offset = 14 + ip_header_length
        src_port, dest_port = struct.unpack_from("!HH", packet, transport_offset)
        occurred_at = datetime.fromtimestamp(seconds, UTC) + timedelta(microseconds=micros)
        flows.append(
            NetworkFlow(
                id=f"packet-{index}",
                analysis_id=path.name,
                sources=["corpus"],
                external_ids=[str(index)],
                start_time=occurred_at,
                end_time=occurred_at,
                src_ip=socket.inet_ntoa(packet[26:30]),
                src_port=src_port,
                dest_ip=socket.inet_ntoa(packet[30:34]),
                dest_port=dest_port,
                transport="tcp",
                application=None,
                src_bytes=len(packet),
                dest_bytes=0,
                src_packets=1,
                dest_packets=0,
                evidence_refs=[f"packet:{index}"],
            )
        )
    return flows
