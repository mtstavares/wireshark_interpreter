from __future__ import annotations

import json
import shutil
import socket
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from backend.app.domain.validation import (
    AnalystConclusion,
    Validation,
    ValidationStatus,
    ValidationTechnicalResult,
)
from backend.app.infrastructure.database import FindingRepository, ValidationRepository

SUPPORTED_VALIDATORS = {"tcp-connect"}
APPROVAL_PHRASE = "AUTORIZADO"


class ValidationError(Exception):
    pass


class ValidationNotFoundError(ValidationError):
    pass


class ValidationStateError(ValidationError):
    pass


class ValidationAuthorizationError(ValidationError):
    pass


@dataclass(frozen=True, slots=True)
class ValidationPolicy:
    active_enabled: bool = False
    allow_public_targets: bool = False
    allowed_networks: tuple[str, ...] = ()
    allowed_ports: tuple[int, ...] = ()
    validators: tuple[str, ...] = ("tcp-connect",)
    timeout_seconds: float = 3.0
    execution_backend: str = "docker"
    docker_image: str = "pcap-validator:local"
    docker_network: str = "pcap-validation-egress"

    @classmethod
    def load(cls, path: Path | None) -> ValidationPolicy:
        if path is None:
            return cls()
        try:
            parsed: Any = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid validation policy: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ValueError("Validation policy must be a JSON object")
        raw = cast(dict[str, Any], parsed)
        networks = tuple(str(value) for value in _list(raw.get("allowed_networks")))
        for value in networks:
            ip_network(value, strict=False)
        ports = tuple(int(str(value)) for value in _list(raw.get("allowed_ports")))
        if any(port < 1 or port > 65535 for port in ports):
            raise ValueError("Validation policy ports must be between 1 and 65535")
        validators = tuple(str(value) for value in _list(raw.get("validators"))) or ("tcp-connect",)
        unsupported = set(validators) - SUPPORTED_VALIDATORS
        if unsupported:
            raise ValueError(
                "Unsupported validation policy validator(s): " + ", ".join(sorted(unsupported))
            )
        timeout = float(raw.get("timeout_seconds", 3.0))
        if timeout <= 0 or timeout > 10:
            raise ValueError("Validation timeout must be greater than 0 and at most 10 seconds")
        backend = str(raw.get("execution_backend", "docker"))
        if backend not in {"docker", "process"}:
            raise ValueError("Validation execution_backend must be docker or process")
        return cls(
            active_enabled=bool(raw.get("active_enabled", False)),
            allow_public_targets=bool(raw.get("allow_public_targets", False)),
            allowed_networks=networks,
            allowed_ports=ports,
            validators=validators,
            timeout_seconds=timeout,
            execution_backend=backend,
            docker_image=str(raw.get("docker_image", "pcap-validator:local")),
            docker_network=str(raw.get("docker_network", "pcap-validation-egress")),
        )

    def evaluate(self, target_ip: str, target_port: int, validator: str) -> tuple[bool, str]:
        try:
            address = ip_address(target_ip)
        except ValueError:
            return False, "Target must be an IP literal; hostnames are not accepted"
        if validator not in self.validators:
            return False, "Validator is not enabled by policy"
        if target_port not in self.allowed_ports:
            return False, "Target port is outside the validation allowlist"
        if not any(
            address in ip_network(network, strict=False) for network in self.allowed_networks
        ):
            return False, "Target IP is outside the validation allowlist"
        if address.is_global and not self.allow_public_targets:
            return False, "Public targets are disabled by policy"
        if not self.active_enabled:
            return False, "Active validation is disabled by policy"
        return True, "Target, port and validator are explicitly allowlisted"


class ValidationService:
    def __init__(
        self,
        finding_repository: FindingRepository,
        validation_repository: ValidationRepository,
        policy: ValidationPolicy,
    ) -> None:
        self._finding_repository = finding_repository
        self._repository = validation_repository
        self._policy = policy

    def plan(
        self,
        finding_id: str,
        *,
        validator: str,
        authorization_confirmed: bool,
        scope_reference: str,
        requested_by: str,
    ) -> Validation:
        if not authorization_confirmed:
            raise ValidationAuthorizationError(
                "Explicit authorization confirmation is required even for planning"
            )
        if len(scope_reference.strip()) < 5:
            raise ValidationAuthorizationError("A scope reference is required")
        if len(requested_by.strip()) < 2:
            raise ValidationAuthorizationError("The requester identity is required")
        finding = self._finding_repository.get(finding_id)
        if finding is None:
            raise ValidationNotFoundError(finding_id)
        if finding.destination_ip is None or finding.destination_port is None:
            raise ValidationStateError(
                "Finding has no exact destination IP and port eligible for validation"
            )
        if validator not in SUPPORTED_VALIDATORS:
            raise ValidationStateError("Unsupported validator")
        allowed, reason = self._policy.evaluate(
            finding.destination_ip, finding.destination_port, validator
        )
        now = datetime.now(UTC)
        validation = Validation(
            id=str(uuid4()),
            analysis_id=finding.analysis_id,
            finding_id=finding.id,
            validator=validator,
            target_ip=finding.destination_ip,
            target_port=finding.destination_port,
            status=(ValidationStatus.AWAITING_APPROVAL if allowed else ValidationStatus.BLOCKED),
            policy_allowed=allowed,
            policy_reason=reason,
            scope_reference=scope_reference.strip(),
            requested_by=requested_by.strip(),
            approved_by=None,
            created_at=now,
            approved_at=None,
            started_at=None,
            completed_at=None,
            technical_result=ValidationTechnicalResult.NOT_EXECUTED,
            analyst_conclusion=AnalystConclusion.PENDING,
            result_summary=None,
            review_rationale=None,
            reviewed_by=None,
            reviewed_at=None,
        )
        return self._repository.create(
            validation,
            action="plan_created",
            actor=requested_by.strip(),
            details={
                "dry_run": True,
                "policy_allowed": allowed,
                "policy_reason": reason,
            },
        )

    def approve(self, validation_id: str, *, phrase: str, approved_by: str) -> Validation:
        validation = self.get(validation_id)
        if validation.status is not ValidationStatus.AWAITING_APPROVAL:
            raise ValidationStateError("Validation is not awaiting approval")
        if phrase != APPROVAL_PHRASE:
            raise ValidationAuthorizationError("The approval phrase is invalid")
        if len(approved_by.strip()) < 2:
            raise ValidationAuthorizationError("The approver identity is required")
        allowed, reason = self._policy.evaluate(
            validation.target_ip,
            validation.target_port,
            validation.validator,
        )
        if not allowed:
            self._repository.block(validation.id, reason, datetime.now(UTC))
            raise ValidationAuthorizationError(reason)
        return self._repository.approve(validation.id, approved_by.strip(), datetime.now(UTC))

    def execute(self, validation_id: str) -> None:
        validation = self.get(validation_id)
        if validation.status is not ValidationStatus.APPROVED:
            raise ValidationStateError("Validation is not approved")
        allowed, reason = self._policy.evaluate(
            validation.target_ip,
            validation.target_port,
            validation.validator,
        )
        if not allowed:
            self._repository.block(validation.id, reason, datetime.now(UTC))
            return
        self._repository.start(validation.id, datetime.now(UTC))
        try:
            if validation.validator != "tcp-connect":
                raise ValidationStateError("Unsupported validator")
            _execute_tcp_validation(validation, self._policy)
        except (TimeoutError, ConnectionError, OSError) as exc:
            self._repository.complete(
                validation.id,
                ValidationTechnicalResult.NOT_REACHABLE,
                (
                    f"TCP connection to {validation.target_ip}:{validation.target_port} "
                    f"did not succeed ({type(exc).__name__}). This result is contextual and "
                    "does not automatically invalidate the finding."
                ),
                datetime.now(UTC),
            )
            return
        except Exception as exc:
            self._repository.complete(
                validation.id,
                ValidationTechnicalResult.ERROR,
                f"Validator failed safely: {type(exc).__name__}: {exc}",
                datetime.now(UTC),
                failed=True,
            )
            return
        self._repository.complete(
            validation.id,
            ValidationTechnicalResult.REACHABLE,
            (
                f"TCP service at {validation.target_ip}:{validation.target_port} accepted a "
                "connection without receiving application payload. Reachability does not "
                "confirm a vulnerability."
            ),
            datetime.now(UTC),
        )

    def review(
        self,
        validation_id: str,
        *,
        conclusion: AnalystConclusion,
        rationale: str,
        reviewed_by: str,
    ) -> Validation:
        validation = self.get(validation_id)
        if validation.status is not ValidationStatus.COMPLETED:
            raise ValidationStateError("Only completed validations can be reviewed")
        if conclusion is AnalystConclusion.PENDING:
            raise ValidationStateError("A terminal analyst conclusion is required")
        if len(rationale.strip()) < 10:
            raise ValidationStateError("Review rationale must contain at least 10 characters")
        if len(reviewed_by.strip()) < 2:
            raise ValidationAuthorizationError("The reviewer identity is required")
        return self._repository.review(
            validation.id,
            conclusion,
            rationale.strip(),
            reviewed_by.strip(),
            datetime.now(UTC),
        )

    def get(self, validation_id: str) -> Validation:
        validation = self._repository.get(validation_id)
        if validation is None:
            raise ValidationNotFoundError(validation_id)
        return validation

    def list(self, analysis_id: str) -> list[Validation]:
        return self._repository.list(analysis_id)


def _list(value: object) -> list[object]:
    return cast(list[object], value) if isinstance(value, list) else []


def _execute_tcp_validation(validation: Validation, policy: ValidationPolicy) -> None:
    if policy.execution_backend == "process":
        with socket.create_connection(
            (validation.target_ip, validation.target_port), timeout=policy.timeout_seconds
        ):
            return
    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError("Docker is required by the hardened validation policy")
    command = [
        docker,
        "run",
        "--rm",
        "--network",
        policy.docker_network,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "32",
        "--memory",
        "64m",
        "--cpus",
        "0.25",
        policy.docker_image,
        validation.target_ip,
        str(validation.target_port),
        str(policy.timeout_seconds),
    ]
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=policy.timeout_seconds + 10,
        shell=False,
    )
    if completed.returncode == 2:
        raise ConnectionError("Isolated TCP connection did not succeed")
    if completed.returncode != 0:
        diagnostic = completed.stderr.decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"Isolated validator failed: {diagnostic}")
