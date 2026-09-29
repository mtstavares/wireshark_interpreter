from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from time import monotonic
from typing import Protocol

from backend.app.domain.analyses import AnalyzerStatus, Artifact

DIAGNOSTIC_LIMIT = 4000


@dataclass(frozen=True, slots=True)
class AnalyzerResult:
    status: AnalyzerStatus
    version: str | None
    duration_ms: int
    exit_code: int | None
    diagnostic: str | None
    artifacts: list[Artifact]


class Analyzer(Protocol):
    name: str

    def analyze(self, capture_path: Path, output_dir: Path, timeout_seconds: int) -> AnalyzerResult:
        ...


class CommandAnalyzer:
    name: str

    def __init__(self, executable: str) -> None:
        self.executable = executable

    def version_arguments(self) -> list[str]:
        raise NotImplementedError

    def analysis_arguments(self, capture_path: Path, output_dir: Path) -> list[str]:
        raise NotImplementedError

    def analyze(self, capture_path: Path, output_dir: Path, timeout_seconds: int) -> AnalyzerResult:
        started = monotonic()
        resolved_executable = shutil.which(self.executable)
        if resolved_executable is None:
            return AnalyzerResult(
                status=AnalyzerStatus.UNAVAILABLE,
                version=None,
                duration_ms=_elapsed_ms(started),
                exit_code=None,
                diagnostic=f"Executable not found: {self.executable}",
                artifacts=[],
            )

        output_dir.mkdir(parents=True, exist_ok=False)
        version = self._read_version(resolved_executable)
        stdout_path = output_dir / "stdout.log"
        stderr_path = output_dir / "stderr.log"
        command = [resolved_executable, *self.analysis_arguments(capture_path, output_dir)]

        try:
            with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
                completed = subprocess.run(
                    command,
                    cwd=output_dir,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    check=False,
                    timeout=timeout_seconds,
                    shell=False,
                )
        except subprocess.TimeoutExpired:
            return AnalyzerResult(
                status=AnalyzerStatus.TIMED_OUT,
                version=version,
                duration_ms=_elapsed_ms(started),
                exit_code=None,
                diagnostic=f"Analyzer exceeded the {timeout_seconds} second timeout",
                artifacts=_artifacts(output_dir),
            )

        diagnostic = _read_diagnostic(stderr_path)
        status = AnalyzerStatus.COMPLETED if completed.returncode == 0 else AnalyzerStatus.FAILED
        return AnalyzerResult(
            status=status,
            version=version,
            duration_ms=_elapsed_ms(started),
            exit_code=completed.returncode,
            diagnostic=diagnostic,
            artifacts=_artifacts(output_dir),
        )

    def _read_version(self, resolved_executable: str) -> str | None:
        try:
            completed = subprocess.run(
                [resolved_executable, *self.version_arguments()],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=10,
                shell=False,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        output = completed.stdout.strip() or completed.stderr.strip()
        return output.splitlines()[0][:300] if output else None


class ZeekAnalyzer(CommandAnalyzer):
    name = "zeek"

    def version_arguments(self) -> list[str]:
        return ["--version"]

    def analysis_arguments(self, capture_path: Path, output_dir: Path) -> list[str]:
        del output_dir
        return ["-C", "-r", str(capture_path), "LogAscii::use_json=T"]


class SuricataAnalyzer(CommandAnalyzer):
    name = "suricata"

    def version_arguments(self) -> list[str]:
        return ["--build-info"]

    def analysis_arguments(self, capture_path: Path, output_dir: Path) -> list[str]:
        return ["-r", str(capture_path), "-l", str(output_dir), "--runmode", "single"]


class TsharkAnalyzer(CommandAnalyzer):
    name = "tshark"

    def version_arguments(self) -> list[str]:
        return ["--version"]

    def analysis_arguments(self, capture_path: Path, output_dir: Path) -> list[str]:
        del output_dir
        fields = [
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
        arguments = [
            "-n",
            "-r",
            str(capture_path),
            "-T",
            "fields",
            "-E",
            "header=y",
            "-E",
            "separator=/t",
            "-E",
            "occurrence=f",
        ]
        for field_name in fields:
            arguments.extend(("-e", field_name))
        return arguments


def _elapsed_ms(started: float) -> int:
    return round((monotonic() - started) * 1000)


def _read_diagnostic(path: Path) -> str | None:
    if not path.exists() or path.stat().st_size == 0:
        return None
    with path.open("rb") as diagnostic_file:
        content = diagnostic_file.read(DIAGNOSTIC_LIMIT)
    return content.decode("utf-8", errors="replace").strip() or None


def _artifacts(output_dir: Path) -> list[Artifact]:
    return [
        Artifact(
            path=str(path.relative_to(output_dir)).replace("\\", "/"),
            size_bytes=path.stat().st_size,
        )
        for path in sorted(output_dir.rglob("*"))
        if path.is_file()
    ]
