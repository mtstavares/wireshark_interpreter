import sys
import threading
import time
from pathlib import Path

from backend.app.analyzers.command import (
    CommandAnalyzer,
    DockerZeekAnalyzer,
    SuricataAnalyzer,
    TsharkAnalyzer,
    ZeekAnalyzer,
)
from backend.app.domain.analyses import AnalyzerStatus


class PythonAnalyzer(CommandAnalyzer):
    name = "python-test"

    def __init__(
        self, script: str, memory_limit_mb: int = 1024, cpu_limit_seconds: int = 240
    ) -> None:
        super().__init__(sys.executable, memory_limit_mb, cpu_limit_seconds)
        self._script = script

    def version_arguments(self) -> list[str]:
        return ["--version"]

    def analysis_arguments(self, capture_path: Path, output_dir: Path) -> list[str]:
        del capture_path, output_dir
        return ["-c", self._script]


def test_zeek_command_uses_offline_json_mode() -> None:
    analyzer = ZeekAnalyzer("zeek")
    arguments = analyzer.analysis_arguments(Path("capture.pcap"), Path("output"))

    assert arguments == ["-C", "-r", "capture.pcap", "LogAscii::use_json=T"]


def test_docker_zeek_is_offline_read_only_and_unprivileged(tmp_path: Path) -> None:
    analyzer = DockerZeekAnalyzer()
    capture = tmp_path / "input" / "capture.pcap"
    output = tmp_path / "analysis" / "zeek"
    arguments = analyzer.analysis_arguments(capture, output)

    assert arguments[:7] == [
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
    ]
    assert "no-new-privileges" in arguments
    assert f"{capture.parent.resolve()}:/input:ro" in arguments
    assert f"{output.resolve()}:/output" in arguments


def test_suricata_command_uses_offline_single_mode() -> None:
    analyzer = SuricataAnalyzer("suricata")
    arguments = analyzer.analysis_arguments(Path("capture.pcap"), Path("output"))

    assert arguments == [
        "-r",
        "capture.pcap",
        "-l",
        "output",
        "--runmode",
        "single",
    ]


def test_tshark_command_disables_resolution_and_outputs_selected_fields() -> None:
    analyzer = TsharkAnalyzer("tshark")
    arguments = analyzer.analysis_arguments(Path("capture.pcap"), Path("output"))

    assert arguments[:12] == [
        "-n",
        "-r",
        "capture.pcap",
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=/t",
        "-E",
        "occurrence=f",
        "-e",
    ]
    assert "frame.number" in arguments
    assert "_ws.col.protocol" in arguments
    assert "snmp.version" in arguments
    assert "tcp.analysis.retransmission" in arguments


def test_missing_executable_is_reported_as_unavailable(tmp_path: Path) -> None:
    analyzer = TsharkAnalyzer("executable-that-does-not-exist-4f55b")

    result = analyzer.analyze(tmp_path / "capture.pcap", tmp_path / "output", 1)

    assert result.status is AnalyzerStatus.UNAVAILABLE
    assert result.exit_code is None
    assert "Executable not found" in (result.diagnostic or "")
    assert not (tmp_path / "output").exists()


def test_command_analyzer_records_artifacts_and_version(tmp_path: Path) -> None:
    analyzer = PythonAnalyzer(
        "from pathlib import Path; Path('artifact.json').write_text('{}'); print('ok')"
    )

    result = analyzer.analyze(tmp_path / "capture.pcap", tmp_path / "output", 5)

    assert result.status is AnalyzerStatus.COMPLETED
    assert result.exit_code == 0
    assert result.version is not None
    assert {artifact.path for artifact in result.artifacts} == {
        "artifact.json",
        "stderr.log",
        "stdout.log",
    }


def test_command_analyzer_records_failure_diagnostic(tmp_path: Path) -> None:
    analyzer = PythonAnalyzer("import sys; print('failure', file=sys.stderr); raise SystemExit(3)")

    result = analyzer.analyze(tmp_path / "capture.pcap", tmp_path / "output", 5)

    assert result.status is AnalyzerStatus.FAILED
    assert result.exit_code == 3
    assert result.diagnostic == "failure"


def test_command_analyzer_enforces_timeout(tmp_path: Path) -> None:
    analyzer = PythonAnalyzer("import time; time.sleep(2)")

    result = analyzer.analyze(tmp_path / "capture.pcap", tmp_path / "output", 1)

    assert result.status is AnalyzerStatus.TIMED_OUT
    assert result.exit_code is None


def test_command_analyzer_enforces_memory_limit(tmp_path: Path) -> None:
    analyzer = PythonAnalyzer("import time; value=bytearray(30_000_000); time.sleep(2)", 20)

    result = analyzer.analyze(tmp_path / "capture.pcap", tmp_path / "analysis" / "python-test", 5)

    assert result.status is AnalyzerStatus.FAILED
    assert "Memory limit exceeded" in (result.diagnostic or "")


def test_command_analyzer_can_cancel_active_process(tmp_path: Path) -> None:
    analyzer = PythonAnalyzer("import time; time.sleep(10)")
    results = []

    thread = threading.Thread(
        target=lambda: results.append(
            analyzer.analyze(
                tmp_path / "capture.pcap", tmp_path / "analysis-id" / "python-test", 20
            )
        )
    )
    thread.start()
    deadline = time.monotonic() + 5
    while thread.is_alive() and time.monotonic() < deadline:
        with analyzer._lock:
            if "analysis-id" in analyzer._active:
                break
        time.sleep(0.01)
    analyzer.cancel("analysis-id")
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert results[0].status is AnalyzerStatus.FAILED
