from __future__ import annotations

import csv
import json
from collections.abc import Iterable, Iterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
from typing import Any, cast
from uuid import NAMESPACE_URL, uuid5

from backend.app.domain.network import NetworkEvent, NetworkFlow
from backend.app.normalization.authentication import TsharkAuthenticationTracker

DETAIL_KEYS = {
    "uid",
    "query",
    "qtype_name",
    "method",
    "host",
    "uri",
    "status_code",
    "server_name",
    "validation_status",
    "note",
    "msg",
}
MAX_FLOW_EVIDENCE_REFS = 100


def parse_zeek_directory(
    analysis_id: str, directory: Path, *, deadline: float | None = None
) -> tuple[list[NetworkFlow], list[NetworkEvent]]:
    flows: list[NetworkFlow] = []
    events: list[NetworkEvent] = []
    for path in sorted(directory.glob("*.log")):
        if path.name in {"stdout.log", "stderr.log"}:
            continue
        for line_number, item in _read_ndjson(path, deadline=deadline):
            reference = f"zeek/{path.name}:{line_number}"
            if path.name == "conn.log":
                flow = _zeek_flow(analysis_id, item, reference)
                if flow is not None:
                    flows.append(flow)
            else:
                events.append(_zeek_event(analysis_id, path.stem, item, reference))
    return flows, events


def parse_suricata_directory(
    analysis_id: str, directory: Path, *, deadline: float | None = None
) -> tuple[list[NetworkFlow], list[NetworkEvent]]:
    path = directory / "eve.json"
    if not path.is_file():
        return [], []
    flows: list[NetworkFlow] = []
    events: list[NetworkEvent] = []
    for line_number, item in _read_ndjson(path, deadline=deadline):
        reference = f"suricata/eve.json:{line_number}"
        if item.get("event_type") == "flow":
            flow = _suricata_flow(analysis_id, item, reference)
            if flow is not None:
                flows.append(flow)
        else:
            events.append(_suricata_event(analysis_id, item, reference))
    return flows, events


def parse_tshark_directory(
    analysis_id: str, directory: Path, *, deadline: float | None = None
) -> tuple[list[NetworkFlow], list[NetworkEvent]]:
    path = directory / "stdout.log"
    if not path.is_file() or path.stat().st_size == 0:
        return [], []
    flows_by_key: dict[tuple[tuple[str, int], tuple[str, int], str], NetworkFlow] = {}
    events: list[NetworkEvent] = []
    authentication = TsharkAuthenticationTracker(analysis_id)
    with path.open(encoding="utf-8", errors="replace", newline="") as source:
        for index, row in enumerate(csv.DictReader(source, delimiter="\t"), start=1):
            if index % 4096 == 0:
                _check_deadline(deadline)
            flow = _tshark_packet_flow(analysis_id, row, index)
            if flow is not None:
                _aggregate_packet(flows_by_key, flow)
            packet_event = _tshark_packet_event(analysis_id, row, index)
            events.append(packet_event)
            events.extend(
                authentication.consume(
                    row,
                    index=index,
                    occurred_at=packet_event.occurred_at,
                    src_ip=packet_event.src_ip,
                    src_port=packet_event.src_port,
                    dest_ip=packet_event.dest_ip,
                    dest_port=packet_event.dest_port,
                )
            )
    events.extend(authentication.finish())
    _check_deadline(deadline)
    return list(flows_by_key.values()), events


def merge_flows(
    analysis_id: str,
    candidates: Iterable[NetworkFlow],
    *,
    deadline: float | None = None,
) -> list[NetworkFlow]:
    priority = {"zeek": 0, "suricata": 1, "tshark": 2}
    ordered = sorted(
        candidates,
        key=lambda flow: (priority.get(flow.sources[0], 99), flow.start_time),
    )
    merged: list[NetworkFlow] = []
    flows_by_key: dict[tuple[tuple[str, int], tuple[str, int], str], list[NetworkFlow]] = {}

    for index, candidate in enumerate(ordered, start=1):
        if index % 4096 == 0:
            _check_deadline(deadline)
        key = _canonical_tuple(candidate)
        bucket = flows_by_key.setdefault(key, [])
        match = next((flow for flow in bucket if _same_communication(flow, candidate)), None)
        if match is None:
            candidate.id = str(uuid5(NAMESPACE_URL, _flow_identity(analysis_id, candidate)))
            merged.append(candidate)
            bucket.append(candidate)
            continue
        match.start_time = min(match.start_time, candidate.start_time)
        match.end_time = max(match.end_time, candidate.end_time)
        same_direction = _directional_tuple(match) == _directional_tuple(candidate)
        candidate_src_bytes = candidate.src_bytes if same_direction else candidate.dest_bytes
        candidate_dest_bytes = candidate.dest_bytes if same_direction else candidate.src_bytes
        candidate_src_packets = candidate.src_packets if same_direction else candidate.dest_packets
        candidate_dest_packets = candidate.dest_packets if same_direction else candidate.src_packets
        match.src_bytes = max(match.src_bytes, candidate_src_bytes)
        match.dest_bytes = max(match.dest_bytes, candidate_dest_bytes)
        match.src_packets = max(match.src_packets, candidate_src_packets)
        match.dest_packets = max(match.dest_packets, candidate_dest_packets)
        match.application = match.application or candidate.application
        match.sources = sorted(
            set(match.sources + candidate.sources),
            key=lambda value: priority.get(value, 99),
        )
        match.external_ids = sorted(set(match.external_ids + candidate.external_ids))
        match.evidence_refs = _merge_evidence_refs(match.evidence_refs, candidate.evidence_refs)
    _check_deadline(deadline)
    return merged


def aggregate_tshark_packets(packets: Iterable[NetworkFlow]) -> list[NetworkFlow]:
    flows_by_key: dict[tuple[tuple[str, int], tuple[str, int], str], NetworkFlow] = {}
    for packet in packets:
        _aggregate_packet(flows_by_key, packet)
    return list(flows_by_key.values())


def _aggregate_packet(
    flows_by_key: dict[tuple[tuple[str, int], tuple[str, int], str], NetworkFlow],
    packet: NetworkFlow,
) -> None:
    key = _canonical_tuple(packet)
    match = flows_by_key.get(key)
    if match is None:
        packet.evidence_refs = packet.evidence_refs[:MAX_FLOW_EVIDENCE_REFS]
        flows_by_key[key] = packet
        return
    same_direction = _directional_tuple(match) == _directional_tuple(packet)
    match.start_time = min(match.start_time, packet.start_time)
    match.end_time = max(match.end_time, packet.end_time)
    if same_direction:
        match.src_bytes += packet.src_bytes
        match.src_packets += packet.src_packets
    else:
        match.dest_bytes += packet.src_bytes
        match.dest_packets += packet.src_packets
    match.evidence_refs = _merge_evidence_refs(match.evidence_refs, packet.evidence_refs)


def _merge_evidence_refs(current: list[str], incoming: Iterable[str]) -> list[str]:
    if len(current) >= MAX_FLOW_EVIDENCE_REFS:
        return current
    seen = set(current)
    for reference in incoming:
        if reference in seen:
            continue
        current.append(reference)
        seen.add(reference)
        if len(current) >= MAX_FLOW_EVIDENCE_REFS:
            break
    return current


def _read_ndjson(
    path: Path, *, deadline: float | None = None
) -> Iterator[tuple[int, dict[str, Any]]]:
    with path.open(encoding="utf-8", errors="replace") as source:
        for line_number, line in enumerate(source, start=1):
            if line_number % 4096 == 0:
                _check_deadline(deadline)
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                yield line_number, item
    _check_deadline(deadline)


def _check_deadline(deadline: float | None) -> None:
    if deadline is not None and monotonic() > deadline:
        raise TimeoutError("Normalization exceeded its configured timeout")


def _zeek_flow(analysis_id: str, item: Mapping[str, Any], reference: str) -> NetworkFlow | None:
    src_ip = _text(item.get("id.orig_h"))
    dest_ip = _text(item.get("id.resp_h"))
    started = _timestamp(item.get("ts"))
    if src_ip is None or dest_ip is None or started is None:
        return None
    duration = _float(item.get("duration")) or 0.0
    external_id = _text(item.get("uid"))
    return NetworkFlow(
        id="",
        analysis_id=analysis_id,
        sources=["zeek"],
        external_ids=[external_id] if external_id else [],
        start_time=started,
        end_time=datetime.fromtimestamp(started.timestamp() + duration, tz=UTC),
        src_ip=src_ip,
        src_port=_int(item.get("id.orig_p")),
        dest_ip=dest_ip,
        dest_port=_int(item.get("id.resp_p")),
        transport=(_text(item.get("proto")) or "unknown").lower(),
        application=_text(item.get("service")),
        src_bytes=_int(item.get("orig_bytes")) or 0,
        dest_bytes=_int(item.get("resp_bytes")) or 0,
        src_packets=_int(item.get("orig_pkts")) or 0,
        dest_packets=_int(item.get("resp_pkts")) or 0,
        evidence_refs=[reference],
    )


def _zeek_event(
    analysis_id: str, event_type: str, item: Mapping[str, Any], reference: str
) -> NetworkEvent:
    return NetworkEvent(
        id=str(uuid5(NAMESPACE_URL, f"{analysis_id}:{reference}")),
        analysis_id=analysis_id,
        source="zeek",
        event_type=event_type,
        occurred_at=_timestamp(item.get("ts")),
        src_ip=_text(item.get("id.orig_h")),
        src_port=_int(item.get("id.orig_p")),
        dest_ip=_text(item.get("id.resp_h")),
        dest_port=_int(item.get("id.resp_p")),
        transport=None,
        application=event_type,
        external_flow_id=_text(item.get("uid")),
        evidence_ref=reference,
        details={key: item[key] for key in DETAIL_KEYS if key in item},
    )


def _suricata_flow(analysis_id: str, item: Mapping[str, Any], reference: str) -> NetworkFlow | None:
    src_ip = _text(item.get("src_ip"))
    dest_ip = _text(item.get("dest_ip"))
    raw_flow_data = item.get("flow")
    flow_data: Mapping[str, Any] = (
        cast(Mapping[str, Any], raw_flow_data) if isinstance(raw_flow_data, Mapping) else {}
    )
    started = _timestamp(flow_data.get("start") or item.get("timestamp"))
    ended = _timestamp(flow_data.get("end")) or started
    if src_ip is None or dest_ip is None or started is None or ended is None:
        return None
    return NetworkFlow(
        id="",
        analysis_id=analysis_id,
        sources=["suricata"],
        external_ids=[str(item["flow_id"])] if "flow_id" in item else [],
        start_time=started,
        end_time=ended,
        src_ip=src_ip,
        src_port=_int(item.get("src_port")),
        dest_ip=dest_ip,
        dest_port=_int(item.get("dest_port")),
        transport=(_text(item.get("proto")) or "unknown").lower(),
        application=_text(item.get("app_proto")),
        src_bytes=_int(flow_data.get("bytes_toserver")) or 0,
        dest_bytes=_int(flow_data.get("bytes_toclient")) or 0,
        src_packets=_int(flow_data.get("pkts_toserver")) or 0,
        dest_packets=_int(flow_data.get("pkts_toclient")) or 0,
        evidence_refs=[reference],
    )


def _suricata_event(analysis_id: str, item: Mapping[str, Any], reference: str) -> NetworkEvent:
    event_type = _text(item.get("event_type")) or "unknown"
    details: dict[str, Any] = {}
    for section in ("alert", "dns", "http", "tls", "fileinfo", "ssh"):
        value = item.get(section)
        if isinstance(value, Mapping):
            details[section] = _sanitize_details(cast(Mapping[str, Any], value))
    return NetworkEvent(
        id=str(uuid5(NAMESPACE_URL, f"{analysis_id}:{reference}")),
        analysis_id=analysis_id,
        source="suricata",
        event_type=event_type,
        occurred_at=_timestamp(item.get("timestamp")),
        src_ip=_text(item.get("src_ip")),
        src_port=_int(item.get("src_port")),
        dest_ip=_text(item.get("dest_ip")),
        dest_port=_int(item.get("dest_port")),
        transport=(_text(item.get("proto")) or "").lower() or None,
        application=_text(item.get("app_proto")),
        external_flow_id=str(item["flow_id"]) if "flow_id" in item else None,
        evidence_ref=reference,
        details=details,
    )


def _tshark_packet_flow(analysis_id: str, row: Mapping[str, Any], index: int) -> NetworkFlow | None:
    transport = "tcp" if row.get("tcp.srcport") else "udp" if row.get("udp.srcport") else "ip"
    src_ip = _text(row.get("ip.src") or row.get("ipv6.src"))
    dest_ip = _text(row.get("ip.dst") or row.get("ipv6.dst"))
    occurred_at = _timestamp(row.get("frame.time_epoch"))
    if src_ip is None or dest_ip is None or occurred_at is None:
        return None
    length = _int(row.get("frame.len")) or 0
    reference = f"tshark/stdout.log:packet:{index}"
    return NetworkFlow(
        id="",
        analysis_id=analysis_id,
        sources=["tshark"],
        external_ids=[],
        start_time=occurred_at,
        end_time=occurred_at,
        src_ip=src_ip,
        src_port=_int(row.get(f"{transport}.srcport")),
        dest_ip=dest_ip,
        dest_port=_int(row.get(f"{transport}.dstport")),
        transport=transport,
        application=_tshark_protocol(row),
        src_bytes=length,
        dest_bytes=0,
        src_packets=1,
        dest_packets=0,
        evidence_refs=[reference],
    )


def _tshark_packet_event(analysis_id: str, row: Mapping[str, Any], index: int) -> NetworkEvent:
    transport = "tcp" if row.get("tcp.srcport") else "udp" if row.get("udp.srcport") else None
    reference = f"tshark/stdout.log:packet:{index}"
    return NetworkEvent(
        id=str(uuid5(NAMESPACE_URL, f"{analysis_id}:{reference}")),
        analysis_id=analysis_id,
        source="tshark",
        event_type="packet",
        occurred_at=_timestamp(row.get("frame.time_epoch")),
        src_ip=_text(row.get("ip.src") or row.get("ipv6.src")),
        src_port=_int(row.get(f"{transport}.srcport")) if transport else None,
        dest_ip=_text(row.get("ip.dst") or row.get("ipv6.dst")),
        dest_port=_int(row.get(f"{transport}.dstport")) if transport else None,
        transport=transport,
        application=_tshark_protocol(row),
        external_flow_id=None,
        evidence_ref=reference,
        details=_tshark_details(row, index),
    )


def _same_communication(left: NetworkFlow, right: NetworkFlow) -> bool:
    if not _same_tuple(left, right):
        return False
    return (left.start_time <= right.end_time and right.start_time <= left.end_time) or abs(
        (left.start_time - right.start_time).total_seconds()
    ) <= 2


def _same_tuple(left: NetworkFlow, right: NetworkFlow) -> bool:
    return _canonical_tuple(left) == _canonical_tuple(right)


def _directional_tuple(flow: NetworkFlow) -> tuple[str, int | None, str, int | None, str]:
    return flow.src_ip, flow.src_port, flow.dest_ip, flow.dest_port, flow.transport


def _canonical_tuple(flow: NetworkFlow) -> tuple[tuple[str, int], tuple[str, int], str]:
    endpoints = sorted(((flow.src_ip, flow.src_port or 0), (flow.dest_ip, flow.dest_port or 0)))
    return endpoints[0], endpoints[1], flow.transport


def _flow_identity(analysis_id: str, flow: NetworkFlow) -> str:
    return f"{analysis_id}:{_canonical_tuple(flow)}:{flow.start_time.isoformat()}"


def _scalar(value: Any) -> Any:
    if isinstance(value, list):
        values = cast(list[Any], value)
        return values[0] if values else None
    return value


def _sanitize_details(value: Mapping[str, Any]) -> dict[str, Any]:
    sensitive_fragments = ("authorization", "cookie", "password", "passwd", "token", "payload")
    return {
        str(key): item
        for key, item in value.items()
        if not any(fragment in str(key).lower() for fragment in sensitive_fragments)
    }


def _tshark_protocol(row: Mapping[str, Any]) -> str | None:
    protocol = _text(row.get("_ws.col.protocol") or row.get("_ws.col.Protocol"))
    return protocol.lower() if protocol else None


def _tshark_details(row: Mapping[str, Any], index: int) -> dict[str, Any]:
    details: dict[str, Any] = {
        "frame_number": _int(row.get("frame.number")) or index,
        "frame_length": _int(row.get("frame.len")) or 0,
    }
    optional = {
        "tcp_syn": _text(row.get("tcp.flags.syn")),
        "tcp_ack": _text(row.get("tcp.flags.ack")),
        "tcp_reset": _text(row.get("tcp.flags.reset")),
        "tcp_retransmission": _text(row.get("tcp.analysis.retransmission")),
        "tcp_stream": _int(row.get("tcp.stream")),
        "snmp_version": _int(row.get("snmp.version")),
        "dns_query": _text(row.get("dns.qry.name")),
    }
    details.update({key: value for key, value in optional.items() if value is not None})
    return details


def _text(value: Any) -> str | None:
    value = _scalar(value)
    if value is None:
        return None
    text = str(value).strip()
    return None if not text or text == "-" else text


def _int(value: Any) -> int | None:
    value = _scalar(value)
    if value is None or value == "-":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float(value: Any) -> float | None:
    value = _scalar(value)
    if value is None or value == "-":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _timestamp(value: Any) -> datetime | None:
    value = _scalar(value)
    if value is None:
        return None
    if isinstance(value, int | float):
        return datetime.fromtimestamp(float(value), tz=UTC)
    text = str(value)
    try:
        return datetime.fromtimestamp(float(text), tz=UTC)
    except ValueError:
        pass
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)
