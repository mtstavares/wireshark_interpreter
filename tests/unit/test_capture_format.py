import pytest

from backend.app.application.ingest_capture import (
    InvalidFilenameError,
    UnsupportedCaptureError,
    detect_capture_format,
    normalize_filename,
)
from backend.app.domain.captures import CaptureFormat


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (bytes.fromhex("d4c3b2a102000400") + bytes(16), CaptureFormat.PCAP),
        (bytes.fromhex("a1b2c3d400020004") + bytes(16), CaptureFormat.PCAP),
        (bytes.fromhex("4d3cb2a102000400") + bytes(16), CaptureFormat.PCAP),
        (bytes.fromhex("a1b23c4d00020004") + bytes(16), CaptureFormat.PCAP),
        (
            bytes.fromhex("0a0d0d0a1c0000004d3c2b1a01000000ffffffffffffffff1c000000"),
            CaptureFormat.PCAPNG,
        ),
    ],
)
def test_detect_capture_format(header: bytes, expected: CaptureFormat) -> None:
    assert detect_capture_format(header) is expected


def test_rejects_unknown_file_signature() -> None:
    with pytest.raises(UnsupportedCaptureError):
        detect_capture_format(b"not-a-pcap")


@pytest.mark.parametrize(
    "content",
    [
        bytes.fromhex("d4c3b2a1"),
        bytes.fromhex("d4c3b2a101000100") + bytes(20),
        bytes.fromhex("0a0d0d0a"),
    ],
)
def test_rejects_truncated_or_malformed_capture_headers(content: bytes) -> None:
    with pytest.raises(UnsupportedCaptureError):
        detect_capture_format(content)


@pytest.mark.parametrize(
    "filename",
    ["../../capture.pcap", "C:\\fakepath\\capture.pcap"],
)
def test_normalizes_path_from_client_filename(filename: str) -> None:
    assert normalize_filename(filename) == "capture.pcap"


@pytest.mark.parametrize("filename", [None, "", "capture.txt", "capture.pcap.exe"])
def test_rejects_invalid_filename(filename: str | None) -> None:
    with pytest.raises(InvalidFilenameError):
        normalize_filename(filename)
