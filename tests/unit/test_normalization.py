import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from backend.app.domain.network import NetworkFlow
from backend.app.normalization.parsers import (
    MAX_FLOW_EVIDENCE_REFS,
    aggregate_tshark_packets,
    merge_flows,
    parse_suricata_directory,
    parse_tshark_directory,
    parse_zeek_directory,
)


def test_aggregates_many_packets_by_index_and_limits_evidence() -> None:
    packets = [
        NetworkFlow(
            id="",
            analysis_id="analysis",
            sources=["tshark"],
            external_ids=[],
            start_time=datetime.fromtimestamp(1_700_000_000 + index / 1000, tz=UTC),
            end_time=datetime.fromtimestamp(1_700_000_000 + index / 1000, tz=UTC),
            src_ip="10.0.0.5" if index % 2 == 0 else "8.8.8.8",
            src_port=51000 if index % 2 == 0 else 53,
            dest_ip="8.8.8.8" if index % 2 == 0 else "10.0.0.5",
            dest_port=53 if index % 2 == 0 else 51000,
            transport="udp",
            application="dns",
            src_bytes=60,
            dest_bytes=0,
            src_packets=1,
            dest_packets=0,
            evidence_refs=[f"packet:{index}"],
        )
        for index in range(10_000)
    ]

    flows = aggregate_tshark_packets(packets)

    assert len(flows) == 1
    assert flows[0].src_packets == 5_000
    assert flows[0].dest_packets == 5_000
    assert len(flows[0].evidence_refs) == MAX_FLOW_EVIDENCE_REFS


def test_tshark_parser_honors_expired_deadline(tmp_path: Path) -> None:
    tshark_dir = tmp_path / "tshark"
    tshark_dir.mkdir()
    (tshark_dir / "stdout.log").write_text(
        "frame.number\tframe.time_epoch\tframe.len\tip.src\tip.dst\n"
        "1\t1700000000.0\t60\t10.0.0.5\t8.8.8.8\n",
        encoding="utf-8",
    )

    with pytest.raises(TimeoutError, match="configured timeout"):
        parse_tshark_directory("analysis", tshark_dir, deadline=0)


def test_parses_and_correlates_zeek_and_suricata_flows(tmp_path: Path) -> None:
    zeek_dir = tmp_path / "zeek"
    suricata_dir = tmp_path / "suricata"
    zeek_dir.mkdir()
    suricata_dir.mkdir()
    (zeek_dir / "conn.log").write_text(
        json.dumps(
            {
                "ts": 1_700_000_000.0,
                "uid": "C1",
                "id.orig_h": "10.0.0.5",
                "id.orig_p": 51000,
                "id.resp_h": "8.8.8.8",
                "id.resp_p": 53,
                "proto": "udp",
                "service": "dns",
                "duration": 0.2,
                "orig_bytes": 40,
                "resp_bytes": 80,
                "orig_pkts": 1,
                "resp_pkts": 1,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (zeek_dir / "dns.log").write_text(
        json.dumps(
            {
                "ts": 1_700_000_000.01,
                "uid": "C1",
                "id.orig_h": "10.0.0.5",
                "id.resp_h": "8.8.8.8",
                "query": "example.com",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (suricata_dir / "eve.json").write_text(
        json.dumps(
            {
                "timestamp": "2023-11-14T22:13:20.050000Z",
                "flow_id": 99,
                "event_type": "flow",
                "src_ip": "10.0.0.5",
                "src_port": 51000,
                "dest_ip": "8.8.8.8",
                "dest_port": 53,
                "proto": "UDP",
                "app_proto": "dns",
                "flow": {
                    "start": "2023-11-14T22:13:20Z",
                    "end": "2023-11-14T22:13:20.200000Z",
                    "bytes_toserver": 40,
                    "bytes_toclient": 80,
                    "pkts_toserver": 1,
                    "pkts_toclient": 1,
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    zeek_flows, zeek_events = parse_zeek_directory("analysis", zeek_dir)
    suricata_flows, _ = parse_suricata_directory("analysis", suricata_dir)
    merged = merge_flows("analysis", [*zeek_flows, *suricata_flows])

    assert len(merged) == 1
    assert merged[0].sources == ["zeek", "suricata"]
    assert merged[0].external_ids == ["99", "C1"]
    assert merged[0].application == "dns"
    assert zeek_events[0].details["query"] == "example.com"


def test_parses_and_aggregates_tshark_tsv(tmp_path: Path) -> None:
    tshark_dir = tmp_path / "tshark"
    tshark_dir.mkdir()
    header = "\t".join(
        [
            "frame.number",
            "frame.time_epoch",
            "frame.len",
            "ip.src",
            "ip.dst",
            "ipv6.src",
            "ipv6.dst",
            "tcp.srcport",
            "tcp.dstport",
            "udp.srcport",
            "udp.dstport",
            "_ws.col.Protocol",
        ]
    )
    rows = [
        ["1", "1700000000.0", "60", "10.0.0.5", "8.8.8.8", "", "", "", "", "51000", "53", "DNS"],
        ["2", "1700000000.1", "90", "8.8.8.8", "10.0.0.5", "", "", "", "", "53", "51000", "DNS"],
    ]
    content = "\n".join([header, *("\t".join(row) for row in rows)]) + "\n"
    (tshark_dir / "stdout.log").write_text(content, encoding="utf-8")

    flows, events = parse_tshark_directory("analysis", tshark_dir)

    assert len(flows) == 1
    assert flows[0].src_bytes == 60
    assert flows[0].dest_bytes == 90
    assert flows[0].src_packets == 1
    assert flows[0].dest_packets == 1
    assert len(events) == 2


def test_correlates_cleartext_ftp_credentials_and_success(tmp_path: Path) -> None:
    tshark_dir = tmp_path / "tshark"
    tshark_dir.mkdir()
    fields = [
        "frame.number",
        "frame.time_epoch",
        "frame.len",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "_ws.col.protocol",
        "tcp.stream",
        "ftp.request.command",
        "ftp.request.arg",
        "ftp.response.code",
    ]
    rows = [
        [
            "1",
            "1700000000.0",
            "60",
            "10.0.0.5",
            "10.0.0.20",
            "51000",
            "21",
            "FTP",
            "7",
            "USER",
            "admin",
            "",
        ],
        [
            "2",
            "1700000000.1",
            "60",
            "10.0.0.5",
            "10.0.0.20",
            "51000",
            "21",
            "FTP",
            "7",
            "PASS",
            "secret",
            "",
        ],
        [
            "3",
            "1700000000.2",
            "60",
            "10.0.0.20",
            "10.0.0.5",
            "21",
            "51000",
            "FTP",
            "7",
            "",
            "",
            "230",
        ],
    ]
    content = "\n".join(["\t".join(fields), *("\t".join(row) for row in rows)]) + "\n"
    (tshark_dir / "stdout.log").write_text(content, encoding="utf-8")

    _, events = parse_tshark_directory("analysis", tshark_dir)

    authentication = [event for event in events if event.event_type == "authentication"]
    assert len(authentication) == 1
    assert authentication[0].src_ip == "10.0.0.5"
    assert authentication[0].dest_ip == "10.0.0.20"
    assert authentication[0].details == {
        "result": "success",
        "credential_transport": "cleartext",
        "request_evidence": "tshark/stdout.log:packet:2",
        "response_evidence": "tshark/stdout.log:packet:3",
        "username": "admin",
        "password": "secret",
    }


def test_http_basic_response_is_only_a_possible_success(tmp_path: Path) -> None:
    tshark_dir = tmp_path / "tshark"
    tshark_dir.mkdir()
    fields = [
        "frame.number",
        "frame.time_epoch",
        "frame.len",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "_ws.col.protocol",
        "tcp.stream",
        "http.authbasic",
        "http.response.code",
    ]
    rows = [
        [
            "1",
            "1700000000.0",
            "80",
            "10.0.0.5",
            "10.0.0.20",
            "51000",
            "80",
            "HTTP",
            "8",
            "admin:secret",
            "",
        ],
        ["2", "1700000000.1", "80", "10.0.0.20", "10.0.0.5", "80", "51000", "HTTP", "8", "", "200"],
    ]
    (tshark_dir / "stdout.log").write_text(
        "\n".join(["\t".join(fields), *("\t".join(row) for row in rows)]) + "\n",
        encoding="utf-8",
    )

    _, events = parse_tshark_directory("analysis", tshark_dir)
    authentication = next(event for event in events if event.event_type == "authentication")

    assert authentication.details["result"] == "possible"
    assert authentication.details["http_status"] == 200
    assert authentication.details["password"] == "secret"


def test_tshark_normalization_preserves_protocol_details_and_skips_non_ip_flows(
    tmp_path: Path,
) -> None:
    tshark_dir = tmp_path / "tshark"
    tshark_dir.mkdir()
    header = "\t".join(
        [
            "frame.number",
            "frame.time_epoch",
            "frame.len",
            "ip.src",
            "ip.dst",
            "ipv6.src",
            "ipv6.dst",
            "tcp.srcport",
            "tcp.dstport",
            "udp.srcport",
            "udp.dstport",
            "_ws.col.protocol",
            "tcp.flags.syn",
            "tcp.flags.ack",
            "tcp.flags.reset",
            "tcp.analysis.retransmission",
            "snmp.version",
            "dns.qry.name",
        ]
    )
    rows = [
        [
            "1",
            "1700000000.0",
            "70",
            "10.0.0.5",
            "10.0.0.10",
            "",
            "",
            "",
            "",
            "50000",
            "161",
            "SNMP",
            "",
            "",
            "",
            "",
            "0",
            "",
        ],
        [
            "2",
            "1700000000.1",
            "68",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "STP",
            "",
            "",
            "",
            "",
            "",
            "",
        ],
    ]
    (tshark_dir / "stdout.log").write_text(
        "\n".join([header, *("\t".join(row) for row in rows)]) + "\n",
        encoding="utf-8",
    )

    flows, events = parse_tshark_directory("analysis", tshark_dir)

    assert len(flows) == 1
    assert flows[0].application == "snmp"
    assert events[0].application == "snmp"
    assert events[0].details["snmp_version"] == 0
    assert events[1].src_ip is None
    assert events[1].application == "stp"
