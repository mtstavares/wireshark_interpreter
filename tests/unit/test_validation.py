import json
from pathlib import Path

import pytest

from backend.app.application.validate_finding import ValidationPolicy


def test_validation_policy_is_deny_by_default() -> None:
    allowed, reason = ValidationPolicy.load(None).evaluate("127.0.0.1", 443, "tcp-connect")

    assert allowed is False
    assert "allowlist" in reason


def test_validation_policy_requires_exact_network_port_and_non_public_target(
    tmp_path: Path,
) -> None:
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            {
                "active_enabled": True,
                "allow_public_targets": False,
                "allowed_networks": ["127.0.0.0/8", "8.8.8.8/32"],
                "allowed_ports": [23],
                "validators": ["tcp-connect"],
                "timeout_seconds": 2,
            }
        ),
        encoding="utf-8",
    )
    policy = ValidationPolicy.load(path)

    assert policy.evaluate("127.0.0.1", 23, "tcp-connect")[0] is True
    assert policy.evaluate("localhost", 23, "tcp-connect")[0] is False
    assert policy.evaluate("127.0.0.1", 22, "tcp-connect")[0] is False
    assert policy.evaluate("10.0.0.1", 23, "tcp-connect")[0] is False
    assert policy.evaluate("8.8.8.8", 23, "tcp-connect")[0] is False


def test_validation_policy_rejects_unsafe_configuration(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text('{"active_enabled":true,"allowed_ports":[70000]}', encoding="utf-8")

    with pytest.raises(ValueError, match="between 1 and 65535"):
        ValidationPolicy.load(path)
