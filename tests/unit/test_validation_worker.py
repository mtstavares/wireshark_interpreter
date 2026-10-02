import socket
import sys

from backend.app import validation_worker


def test_validation_worker_rejects_invalid_arguments(monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["validation_worker", "hostname", "80", "3"])
    assert validation_worker.main() == 2


def test_validation_worker_connects_without_payload(monkeypatch) -> None:
    calls: list[tuple[tuple[str, int], float]] = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

    def connect(target: tuple[str, int], timeout: float):
        calls.append((target, timeout))
        return Connection()

    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(sys, "argv", ["validation_worker", "127.0.0.1", "443", "2"])

    assert validation_worker.main() == 0
    assert calls == [(("127.0.0.1", 443), 2.0)]
