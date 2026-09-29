from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from uuid import uuid4

from fastapi import UploadFile

from backend.app.domain.captures import Capture, CaptureFormat, CaptureStatus
from backend.app.infrastructure.database import CaptureRepository

CHUNK_SIZE = 1024 * 1024
MAX_FILENAME_LENGTH = 255

PCAP_MAGIC_BYTES = {
    bytes.fromhex("d4c3b2a1"),
    bytes.fromhex("a1b2c3d4"),
    bytes.fromhex("4d3cb2a1"),
    bytes.fromhex("a1b23c4d"),
}
PCAPNG_MAGIC_BYTES = bytes.fromhex("0a0d0d0a")


class CaptureIngestionError(Exception):
    status_code = 422
    title = "Invalid capture"


class InvalidFilenameError(CaptureIngestionError):
    title = "Invalid filename"


class UnsupportedCaptureError(CaptureIngestionError):
    title = "Unsupported capture format"


class CaptureTooLargeError(CaptureIngestionError):
    status_code = 413
    title = "Capture is too large"


def detect_capture_format(header: bytes) -> CaptureFormat:
    magic = header[:4]
    if magic in PCAP_MAGIC_BYTES:
        return CaptureFormat.PCAP
    if magic == PCAPNG_MAGIC_BYTES:
        return CaptureFormat.PCAPNG
    raise UnsupportedCaptureError("The file signature is not PCAP or PCAPNG")


def normalize_filename(filename: str | None) -> str:
    if not filename:
        raise InvalidFilenameError("A filename is required")
    normalized = PurePosixPath(filename.replace("\\", "/")).name.strip()
    if not normalized or len(normalized) > MAX_FILENAME_LENGTH:
        raise InvalidFilenameError("The filename is empty or too long")
    if Path(normalized).suffix.lower() not in {".pcap", ".pcapng"}:
        raise InvalidFilenameError("The extension must be .pcap or .pcapng")
    return normalized


class IngestCaptureService:
    def __init__(
        self,
        repository: CaptureRepository,
        captures_dir: Path,
        max_upload_bytes: int,
    ) -> None:
        self._repository = repository
        self._captures_dir = captures_dir
        self._max_upload_bytes = max_upload_bytes

    async def execute(self, upload: UploadFile) -> Capture:
        original_filename = normalize_filename(upload.filename)
        capture_id = str(uuid4())
        temporary_path = self._captures_dir / f".{capture_id}.part"
        size_bytes = 0
        digest = hashlib.sha256()
        header = b""

        try:
            with temporary_path.open("xb") as destination:
                while chunk := await upload.read(CHUNK_SIZE):
                    size_bytes += len(chunk)
                    if size_bytes > self._max_upload_bytes:
                        raise CaptureTooLargeError(
                            f"The maximum upload size is {self._max_upload_bytes} bytes"
                        )
                    if len(header) < 4:
                        header = (header + chunk)[:4]
                    digest.update(chunk)
                    destination.write(chunk)

            capture_format = detect_capture_format(header)
            stored_filename = f"{capture_id}.{capture_format.value}"
            final_path = self._captures_dir / stored_filename
            temporary_path.replace(final_path)

            capture = Capture(
                id=capture_id,
                original_filename=original_filename,
                stored_filename=stored_filename,
                sha256=digest.hexdigest(),
                size_bytes=size_bytes,
                capture_format=capture_format,
                status=CaptureStatus.VALIDATED,
                created_at=datetime.now(UTC),
            )
            try:
                return self._repository.add(capture)
            except Exception:
                final_path.unlink(missing_ok=True)
                raise
        finally:
            temporary_path.unlink(missing_ok=True)
            await upload.close()
