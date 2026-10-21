from __future__ import annotations

from pathlib import Path

from backend.app.launcher import _find_executable


def test_find_executable_uses_known_installation(monkeypatch, tmp_path: Path) -> None:
    executable = tmp_path / "tool.exe"
    executable.write_bytes(b"binary")
    monkeypatch.setattr("backend.app.launcher.shutil.which", lambda _name: None)

    assert _find_executable("tool.exe", [executable]) == str(executable)


def test_find_executable_falls_back_to_name(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("backend.app.launcher.shutil.which", lambda _name: None)

    assert _find_executable("missing.exe", [tmp_path / "missing.exe"]) == "missing.exe"
