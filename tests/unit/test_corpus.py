import hashlib
import json
import struct
from pathlib import Path

from backend.app.evaluation.baseline import quality_baseline
from backend.app.evaluation.corpus import evaluate_corpus, read_pcap_flows

CORPUS = Path("samples/corpus")


def test_corpus_pcaps_are_readable_and_categorized() -> None:
    assert len(read_pcap_flows(CORPUS / "benign-https.pcap")) == 5
    assert len(read_pcap_flows(CORPUS / "malicious-horizontal-scan.pcap")) == 10
    assert len(read_pcap_flows(CORPUS / "malicious-vertical-scan.pcap")) == 15
    telnet = read_pcap_flows(CORPUS / "malicious-telnet.pcap")
    assert len(telnet) > 1
    assert any(flow.application == "telnet" for flow in telnet)
    expected = json.loads(
        (CORPUS / "comprehensive-attacks.expected.json").read_text(encoding="utf-8")
    )
    payload = (CORPUS / "comprehensive-attacks.pcap").read_bytes()
    assert hashlib.sha256(payload).hexdigest() == expected["sha256"]
    offset = 24
    packets = 0
    while offset + 16 <= len(payload):
        included_length = struct.unpack_from("<I", payload, offset + 8)[0]
        offset += 16 + included_length
        packets += 1
    assert packets == expected["packet_count"] == 367
    scenario_ids = {scenario["id"] for scenario in expected["scenarios"]}
    assert {
        "sql-injection",
        "ftp-brute-force-success",
        "telnet-brute-force-success",
    } <= scenario_ids
    baseline = quality_baseline()
    assert baseline["capture_sha256"] == expected["sha256"]
    assert baseline["true_positive"] == sum(
        item.get("count", 1) for item in expected["expected_findings"]
    )


def test_detector_regression_metrics_have_no_known_errors() -> None:
    metrics = evaluate_corpus(CORPUS)

    assert metrics.true_positive == 5
    assert metrics.false_positive == 0
    assert metrics.false_negative == 0
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
