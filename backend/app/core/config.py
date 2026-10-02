from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _positive_int(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    data_dir: Path
    max_upload_bytes: int = 100 * 1024 * 1024
    log_level: str = "INFO"
    analyzer_timeout_seconds: int = 300
    normalization_timeout_seconds: int = 900
    analyzer_memory_limit_mb: int = 1024
    analyzer_cpu_limit_seconds: int = 240
    retention_days: int = 30
    auth_username: str | None = None
    auth_password: str | None = None
    zeek_binary: str = "zeek"
    suricata_binary: str = "suricata"
    tshark_binary: str = "tshark"
    asset_context_path: Path | None = None
    reputation_path: Path | None = None
    enrichment_catalog_path: Path | None = None
    validation_policy_path: Path | None = None
    credential_policy_path: Path | None = None

    @classmethod
    def from_env(cls) -> Settings:
        asset_context = os.getenv("PCAP_ASSET_CONTEXT_FILE")
        reputation = os.getenv("PCAP_REPUTATION_FILE")
        enrichment_catalog = os.getenv("PCAP_ENRICHMENT_CATALOG_FILE")
        validation_policy = os.getenv("PCAP_VALIDATION_POLICY_FILE")
        credential_policy = os.getenv("PCAP_CREDENTIAL_POLICY_FILE")
        return cls(
            data_dir=Path(os.getenv("PCAP_DATA_DIR", ".data")).resolve(),
            max_upload_bytes=_positive_int("PCAP_MAX_UPLOAD_BYTES", 100 * 1024 * 1024),
            log_level=os.getenv("PCAP_LOG_LEVEL", "INFO").upper(),
            analyzer_timeout_seconds=_positive_int("PCAP_ANALYZER_TIMEOUT_SECONDS", 300),
            normalization_timeout_seconds=_positive_int("PCAP_NORMALIZATION_TIMEOUT_SECONDS", 900),
            analyzer_memory_limit_mb=_positive_int("PCAP_ANALYZER_MEMORY_LIMIT_MB", 1024),
            analyzer_cpu_limit_seconds=_positive_int("PCAP_ANALYZER_CPU_LIMIT_SECONDS", 240),
            retention_days=_positive_int("PCAP_RETENTION_DAYS", 30),
            auth_username=os.getenv("PCAP_AUTH_USERNAME") or None,
            auth_password=os.getenv("PCAP_AUTH_PASSWORD") or None,
            zeek_binary=os.getenv("PCAP_ZEEK_BINARY", "zeek"),
            suricata_binary=os.getenv("PCAP_SURICATA_BINARY", "suricata"),
            tshark_binary=os.getenv("PCAP_TSHARK_BINARY", "tshark"),
            asset_context_path=Path(asset_context).resolve() if asset_context else None,
            reputation_path=Path(reputation).resolve() if reputation else None,
            enrichment_catalog_path=(
                Path(enrichment_catalog).resolve() if enrichment_catalog else None
            ),
            validation_policy_path=(
                Path(validation_policy).resolve() if validation_policy else None
            ),
            credential_policy_path=(
                Path(credential_policy).resolve() if credential_policy else None
            ),
        )

    @property
    def captures_dir(self) -> Path:
        return self.data_dir / "captures"

    @property
    def database_path(self) -> Path:
        return self.data_dir / "app.db"

    @property
    def analyses_dir(self) -> Path:
        return self.data_dir / "analyses"

    def ensure_directories(self) -> None:
        self.captures_dir.mkdir(parents=True, exist_ok=True)
        self.analyses_dir.mkdir(parents=True, exist_ok=True)
