from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class CaptureFormat(StrEnum):
    PCAP = "pcap"
    PCAPNG = "pcapng"


class CaptureStatus(StrEnum):
    VALIDATED = "validated"


@dataclass(frozen=True, slots=True)
class Capture:
    id: str
    original_filename: str
    stored_filename: str
    sha256: str
    size_bytes: int
    capture_format: CaptureFormat
    status: CaptureStatus
    created_at: datetime

