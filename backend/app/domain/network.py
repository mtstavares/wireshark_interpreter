from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class NormalizationStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class NormalizationSummary:
    status: NormalizationStatus
    flow_count: int = 0
    event_count: int = 0
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None


@dataclass(slots=True)
class NetworkFlow:
    id: str
    analysis_id: str
    sources: list[str]
    external_ids: list[str]
    start_time: datetime
    end_time: datetime
    src_ip: str
    src_port: int | None
    dest_ip: str
    dest_port: int | None
    transport: str
    application: str | None
    src_bytes: int
    dest_bytes: int
    src_packets: int
    dest_packets: int
    evidence_refs: list[str] = field(default_factory=list[str])


@dataclass(frozen=True, slots=True)
class NetworkEvent:
    id: str
    analysis_id: str
    source: str
    event_type: str
    occurred_at: datetime | None
    src_ip: str | None
    src_port: int | None
    dest_ip: str | None
    dest_port: int | None
    transport: str | None
    application: str | None
    external_flow_id: str | None
    evidence_ref: str
    details: dict[str, Any]


@dataclass(frozen=True, slots=True)
class HostInventory:
    ip: str
    first_seen: datetime
    last_seen: datetime
    sent_bytes: int
    received_bytes: int
    transports: list[str]
    applications: list[str]


@dataclass(frozen=True, slots=True)
class ServiceInventory:
    ip: str
    port: int
    transport: str
    application: str | None
    flow_count: int


@dataclass(frozen=True, slots=True)
class NetworkInventory:
    hosts: list[HostInventory]
    services: list[ServiceInventory]

