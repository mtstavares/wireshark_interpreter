from __future__ import annotations

import argparse
import json
import os
import struct
import tempfile
import threading
import time
from pathlib import Path

import psutil
from fastapi.testclient import TestClient

from backend.app.analyzers.command import TsharkAnalyzer
from backend.app.core.config import Settings
from backend.app.main import create_app

PCAP_HEADER = bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000")
PACKET = bytes.fromhex(
    "00112233445566778899aabb08004500002800010000400666cd0a0000010a000002"
    "c35001bb00000000000000005002faf000000000"
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark end-to-end PCAP processing")
    parser.add_argument("--sizes-mb", nargs="+", type=int, default=[1, 10, 50])
    parser.add_argument("--output", default="reports/benchmark.json")
    args = parser.parse_args()
    results: list[dict[str, int | float | str]] = []
    tshark = os.getenv("PCAP_TSHARK_BINARY", "tshark")
    with tempfile.TemporaryDirectory(prefix="pcap-benchmark-") as temporary:
        root = Path(temporary)
        settings = Settings(
            data_dir=root / "data",
            max_upload_bytes=(max(args.sizes_mb) + 1) * 1024 * 1024,
            tshark_binary=tshark,
        )
        app = create_app(settings, analyzers=[TsharkAnalyzer(tshark)])
        with TestClient(app) as client:
            for size_mb in args.sizes_mb:
                capture_path = root / f"benchmark-{size_mb}mb.pcap"
                _generate(capture_path, size_mb * 1024 * 1024)
                peak_rss = [psutil.Process().memory_info().rss]
                stop = threading.Event()
                sampler = threading.Thread(target=_sample_memory, args=(stop, peak_rss))
                sampler.start()
                started = time.perf_counter()
                with capture_path.open("rb") as source:
                    uploaded = client.post(
                        "/api/v1/captures",
                        files={"file": (capture_path.name, source, "application/octet-stream")},
                    ).json()
                created = client.post(
                    f"/api/v1/captures/{uploaded['id']}/analyses"
                ).json()
                analysis = client.get(f"/api/v1/analyses/{created['id']}").json()
                elapsed = time.perf_counter() - started
                stop.set()
                sampler.join()
                data_size = sum(
                    path.stat().st_size for path in settings.data_dir.rglob("*") if path.is_file()
                )
                results.append(
                    {
                        "capture": capture_path.name,
                        "input_bytes": capture_path.stat().st_size,
                        "elapsed_seconds": round(elapsed, 3),
                        "peak_rss_bytes": peak_rss[0],
                        "database_bytes": settings.database_path.stat().st_size,
                        "data_directory_bytes": data_size,
                        "analysis_status": analysis["status"],
                    }
                )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(output.resolve())


def _generate(path: Path, target_size: int) -> None:
    record = struct.pack("<IIII", 1_700_000_000, 0, len(PACKET), len(PACKET)) + PACKET
    with path.open("wb") as destination:
        destination.write(PCAP_HEADER)
        while destination.tell() + len(record) <= target_size:
            destination.write(record)


def _sample_memory(stop: threading.Event, peak: list[int]) -> None:
    process = psutil.Process()
    while not stop.wait(0.05):
        processes = [process, *process.children(recursive=True)]
        rss = sum(item.memory_info().rss for item in processes if item.is_running())
        peak[0] = max(peak[0], rss)


if __name__ == "__main__":
    main()
