from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from time import monotonic
from typing import Protocol

import psutil

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

    def analyze(
        self, capture_path: Path, output_dir: Path, timeout_seconds: int
    ) -> AnalyzerResult: ...


class CommandAnalyzer:
    name: str

    def __init__(
        self,
        executable: str,
        memory_limit_mb: int = 1024,
        cpu_limit_seconds: int = 240,
    ) -> None:
        self.executable = executable
        self._memory_limit_bytes = memory_limit_mb * 1024 * 1024
        self._cpu_limit_seconds = cpu_limit_seconds
        self._active: dict[str, subprocess.Popen[bytes]] = {}
        self._lock = threading.Lock()

    def cancel(self, analysis_id: str) -> None:
        with self._lock:
            process = self._active.get(analysis_id)
        if process is not None:
            _terminate_tree(process)

    def version_arguments(self) -> list[str]:
        raise NotImplementedError

    def analysis_arguments(self, capture_path: Path, output_dir: Path) -> list[str]:
        raise NotImplementedError

    def execution_environment(self, resolved_executable: str) -> dict[str, str] | None:
        del resolved_executable
        return None

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

        analysis_id = output_dir.parent.name
        limit_diagnostic: str | None = None
        try:
            with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
                process = subprocess.Popen(
                    command,
                    cwd=output_dir,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    shell=False,
                    env=self.execution_environment(resolved_executable),
                )
                with self._lock:
                    self._active[analysis_id] = process
                try:
                    limit_diagnostic = _wait_with_limits(
                        process,
                        timeout_seconds,
                        self._memory_limit_bytes,
                        self._cpu_limit_seconds,
                    )
                finally:
                    with self._lock:
                        self._active.pop(analysis_id, None)
        except OSError as exc:
            return AnalyzerResult(
                status=AnalyzerStatus.FAILED,
                version=version,
                duration_ms=_elapsed_ms(started),
                exit_code=None,
                diagnostic=f"Analyzer could not start: {type(exc).__name__}: {exc}",
                artifacts=_artifacts(output_dir),
            )

        diagnostic = _read_diagnostic(stderr_path)
        if limit_diagnostic is not None:
            status = (
                AnalyzerStatus.TIMED_OUT
                if limit_diagnostic.startswith("Wall-clock")
                else AnalyzerStatus.FAILED
            )
            diagnostic = limit_diagnostic
        else:
            status = AnalyzerStatus.COMPLETED if process.returncode == 0 else AnalyzerStatus.FAILED
        return AnalyzerResult(
            status=status,
            version=version,
            duration_ms=_elapsed_ms(started),
            exit_code=None if limit_diagnostic is not None else process.returncode,
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
                env=self.execution_environment(resolved_executable),
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        output = completed.stdout.strip() or completed.stderr.strip()
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if not lines:
            return None
        return lines[0][:300]


class ZeekAnalyzer(CommandAnalyzer):
    name = "zeek"

    def version_arguments(self) -> list[str]:
        return ["--version"]

    def analysis_arguments(self, capture_path: Path, output_dir: Path) -> list[str]:
        del output_dir
        return ["-C", "-r", str(capture_path), "LogAscii::use_json=T"]


class DockerZeekAnalyzer(CommandAnalyzer):
    name = "zeek"

    def __init__(
        self,
        image: str = "zeek/zeek:lts",
        memory_limit_mb: int = 1024,
        cpu_limit_seconds: int = 240,
    ) -> None:
        super().__init__("docker", memory_limit_mb, cpu_limit_seconds)
        self._image = image

    def version_arguments(self) -> list[str]:
        return ["run", "--rm", "--network", "none", self._image, "zeek", "--version"]

    def analysis_arguments(self, capture_path: Path, output_dir: Path) -> list[str]:
        return [
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--memory",
            f"{self._memory_limit_bytes}",
            "--cpus",
            "1",
            "-v",
            f"{capture_path.parent.resolve()}:/input:ro",
            "-v",
            f"{output_dir.resolve()}:/output",
            "-w",
            "/output",
            self._image,
            "zeek",
            "-C",
            "-r",
            f"/input/{capture_path.name}",
            "LogAscii::use_json=T",
        ]


class SuricataAnalyzer(CommandAnalyzer):
    name = "suricata"

    def version_arguments(self) -> list[str]:
        return ["-V"]

    def _read_version(self, resolved_executable: str) -> str | None:
        version = super()._read_version(resolved_executable)
        if version is None or "win32-service" not in version:
            return version
        try:
            completed = subprocess.run(
                [resolved_executable, "-V"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=10,
                shell=False,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=self.execution_environment(resolved_executable),
            )
        except (OSError, subprocess.TimeoutExpired):
            return version
        lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
        return next((line[:300] for line in lines if "Suricata version" in line), version)

    def analysis_arguments(self, capture_path: Path, output_dir: Path) -> list[str]:
        return ["-r", str(capture_path), "-l", str(output_dir), "--runmode", "single"]

    def execution_environment(self, resolved_executable: str) -> dict[str, str] | None:
        if os.name != "nt":
            return None
        environment = os.environ.copy()
        dependencies = [str(Path(resolved_executable).parent), r"C:\Windows\System32\Npcap"]
        environment["PATH"] = os.pathsep.join([*dependencies, environment.get("PATH", "")])
        return environment


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
            "tcp.stream",
            "snmp.version",
            "dns.qry.name",
            "ftp.request.command",
            "ftp.request.arg",
            "ftp.response.code",
            "ftp.response.arg",
            "http.authbasic",
            "http.authorization",
            "http.proxy_authorization",
            "http.request.method",
            "http.response.code",
            "imap.request.command",
            "imap.request.username",
            "imap.request.password",
            "imap.response.status",
            "pop.request.command",
            "pop.request.parameter",
            "pop.response.indicator",
            "pop.response.description",
            "smtp.req.command",
            "smtp.auth.username",
            "smtp.auth.password",
            "smtp.auth.username_password",
            "smtp.response.code",
            "smtp.rsp.parameter",
            "telnet.data",
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


def _wait_with_limits(
    process: subprocess.Popen[bytes],
    timeout_seconds: int,
    memory_limit_bytes: int,
    cpu_limit_seconds: int,
) -> str | None:
    started = monotonic()
    monitored = psutil.Process(process.pid)
    while process.poll() is None:
        if monotonic() - started > timeout_seconds:
            _terminate_tree(process)
            return f"Wall-clock limit exceeded ({timeout_seconds} seconds)"
        try:
            processes = [monitored, *monitored.children(recursive=True)]
            rss = sum(item.memory_info().rss for item in processes if item.is_running())
            cpu = sum(
                item.cpu_times().user + item.cpu_times().system
                for item in processes
                if item.is_running()
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            process.wait()
            break
        if rss > memory_limit_bytes:
            _terminate_tree(process)
            return f"Memory limit exceeded ({memory_limit_bytes // (1024 * 1024)} MiB)"
        if cpu > cpu_limit_seconds:
            _terminate_tree(process)
            return f"CPU-time limit exceeded ({cpu_limit_seconds} seconds)"
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=0.1)
    return None


def _terminate_tree(process: subprocess.Popen[bytes]) -> None:
    try:
        parent = psutil.Process(process.pid)
        children = parent.children(recursive=True)
        for child in children:
            child.terminate()
        parent.terminate()
        _, alive = psutil.wait_procs([*children, parent], timeout=2)
        for item in alive:
            item.kill()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        process.kill()
    process.wait(timeout=5)


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
