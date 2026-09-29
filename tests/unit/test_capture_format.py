import pytest

from backend.app.application.ingest_capture import (
    InvalidFilenameError,
    UnsupportedCaptureError,
    detect_capture_format,
    normalize_filename,
)
from backend.app.domain.captures import CaptureFormat


@pytest.mark.parametrize(
    ("magic", "expected"),
    [
        (bytes.fromhex("d4c3b2a1"), CaptureFormat.PCAP),
        (bytes.fromhex("a1b2c3d4"), CaptureFormat.PCAP),
        (bytes.fromhex("4d3cb2a1"), CaptureFormat.PCAP),
        (bytes.fromhex("a1b23c4d"), CaptureFormat.PCAP),
        (bytes.fromhex("0a0d0d0a"), CaptureFormat.PCAPNG),
    ],
)
def test_detect_capture_format(magic: bytes, expected: CaptureFormat) -> None:
    assert detect_capture_format(magic + b"payload") is expected


def test_rejects_unknown_file_signature() -> None:
    with pytest.raises(UnsupportedCaptureError):
        detect_capture_format(b"not-a-pcap")


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
