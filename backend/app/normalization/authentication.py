from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from backend.app.domain.network import NetworkEvent

MAX_CREDENTIAL_LENGTH = 512


@dataclass(slots=True)
class _PendingAuthentication:
    application: str
    client_ip: str
    client_port: int | None
    server_ip: str
    server_port: int | None
    occurred_at: datetime | None
    evidence_ref: str
    username: str | None = None
    password: str | None = None
    telnet_expected: str | None = None


class TsharkAuthenticationTracker:
    """Correlates cleartext authentication fields without retaining raw packet payloads."""

    def __init__(self, analysis_id: str) -> None:
        self._analysis_id = analysis_id
        self._pending: dict[str, _PendingAuthentication] = {}

    def consume(
        self,
        row: Mapping[str, Any],
        *,
        index: int,
        occurred_at: datetime | None,
        src_ip: str | None,
        src_port: int | None,
        dest_ip: str | None,
        dest_port: int | None,
    ) -> list[NetworkEvent]:
        if src_ip is None or dest_ip is None:
            return []
        reference = f"tshark/stdout.log:packet:{index}"
        stream = _value(row, "tcp.stream")
        key = stream or _conversation_key(src_ip, src_port, dest_ip, dest_port)
        protocol = _protocol(row, src_port, dest_port)
        if protocol is None:
            return []

        pending = self._pending.get(key)
        if protocol == "http":
            credentials = _http_credentials(row)
            if credentials is not None:
                username, password = credentials
                self._pending[key] = _PendingAuthentication(
                    protocol,
                    src_ip,
                    src_port,
                    dest_ip,
                    dest_port,
                    occurred_at,
                    reference,
                    username,
                    password,
                )
                return []
            status = _int_value(row, "http.response.code")
            if pending is not None and pending.application == "http" and status is not None:
                outcome = (
                    "failure"
                    if status in {401, 403, 407}
                    else "possible"
                    if 200 <= status < 400
                    else "unknown"
                )
                self._pending.pop(key, None)
                return [self._event(pending, outcome, reference, http_status=status)]
            return []

        if pending is None:
            client_ip, client_port, server_ip, server_port = _orient_endpoints(
                protocol, src_ip, src_port, dest_ip, dest_port
            )
            pending = _PendingAuthentication(
                protocol,
                client_ip,
                client_port,
                server_ip,
                server_port,
                occurred_at,
                reference,
            )
            self._pending[key] = pending

        if protocol == "ftp":
            command = (_value(row, "ftp.request.command") or "").upper()
            argument = _value(row, "ftp.request.arg")
            if command == "USER":
                pending.username = argument
                pending.evidence_ref = reference
            elif command == "PASS":
                pending.password = argument
                pending.evidence_ref = reference
            code = _int_value(row, "ftp.response.code")
            if pending.password is not None and code in {230, 232}:
                return self._complete(key, pending, "success", reference)
            if pending.password is not None and code in {430, 530, 532}:
                return self._complete(key, pending, "failure", reference)

        elif protocol == "pop3":
            command = (_value(row, "pop.request.command") or "").upper()
            parameter = _value(row, "pop.request.parameter")
            if command == "USER":
                pending.username = parameter
                pending.evidence_ref = reference
            elif command == "PASS":
                pending.password = parameter
                pending.evidence_ref = reference
            indicator = (_value(row, "pop.response.indicator") or "").upper()
            if pending.password is not None and indicator.startswith("+OK"):
                return self._complete(key, pending, "success", reference)
            if pending.password is not None and indicator.startswith("-ERR"):
                return self._complete(key, pending, "failure", reference)

        elif protocol == "imap":
            username = _value(row, "imap.request.username")
            password = _value(row, "imap.request.password")
            if username is not None:
                pending.username = username
            if password is not None:
                pending.password = password
                pending.evidence_ref = reference
            status = (_value(row, "imap.response.status") or "").upper()
            if pending.password is not None and status == "OK":
                return self._complete(key, pending, "success", reference)
            if pending.password is not None and status in {"NO", "BAD"}:
                return self._complete(key, pending, "failure", reference)

        elif protocol == "smtp":
            username = _value(row, "smtp.auth.username")
            password = _value(row, "smtp.auth.password")
            combined = _value(row, "smtp.auth.username_password")
            if combined and ":" in combined:
                username, password = combined.split(":", 1)
            if username is not None:
                pending.username = username
            if password is not None:
                pending.password = password
                pending.evidence_ref = reference
            code = _int_value(row, "smtp.response.code")
            if pending.password is not None and code == 235:
                return self._complete(key, pending, "success", reference)
            if pending.password is not None and code in {432, 454, 534, 535, 538}:
                return self._complete(key, pending, "failure", reference)

        elif protocol == "telnet":
            data = _value(row, "telnet.data")
            if data:
                normalized = " ".join(data.replace("\r", " ").replace("\n", " ").split())
                lower = normalized.lower()
                from_server = src_ip == pending.server_ip and src_port == pending.server_port
                if from_server:
                    if "password:" in lower:
                        pending.telnet_expected = "password"
                    elif "login:" in lower or "username:" in lower:
                        pending.telnet_expected = "username"
                    if pending.password is not None:
                        if any(
                            term in lower
                            for term in ("login incorrect", "login failed", "access denied")
                        ):
                            return self._complete(key, pending, "failure", reference)
                        if any(
                            term in lower for term in ("login successful", "last login", "welcome")
                        ):
                            return self._complete(key, pending, "success", reference)
                elif pending.telnet_expected and normalized:
                    value = normalized[:MAX_CREDENTIAL_LENGTH]
                    if pending.telnet_expected == "username":
                        pending.username = value
                    else:
                        pending.password = value
                    pending.telnet_expected = None
                    pending.evidence_ref = reference
        return []

    def finish(self) -> list[NetworkEvent]:
        events = [
            self._event(pending, "unknown", pending.evidence_ref)
            for pending in self._pending.values()
            if pending.username is not None or pending.password is not None
        ]
        self._pending.clear()
        return events

    def _complete(
        self,
        key: str,
        pending: _PendingAuthentication,
        outcome: str,
        response_reference: str,
    ) -> list[NetworkEvent]:
        self._pending.pop(key, None)
        return [self._event(pending, outcome, response_reference)]

    def _event(
        self,
        pending: _PendingAuthentication,
        outcome: str,
        response_reference: str,
        *,
        http_status: int | None = None,
    ) -> NetworkEvent:
        details: dict[str, Any] = {
            "result": outcome,
            "credential_transport": "cleartext",
            "request_evidence": pending.evidence_ref,
            "response_evidence": response_reference,
        }
        if pending.username is not None:
            details["username"] = pending.username[:MAX_CREDENTIAL_LENGTH]
        if pending.password is not None:
            details["password"] = pending.password[:MAX_CREDENTIAL_LENGTH]
        if http_status is not None:
            details["http_status"] = http_status
        identity = (
            f"{self._analysis_id}:{pending.application}:{pending.evidence_ref}:"
            f"{response_reference}:{pending.username}:{outcome}"
        )
        return NetworkEvent(
            id=str(uuid5(NAMESPACE_URL, identity)),
            analysis_id=self._analysis_id,
            source="tshark",
            event_type="authentication",
            occurred_at=pending.occurred_at,
            src_ip=pending.client_ip,
            src_port=pending.client_port,
            dest_ip=pending.server_ip,
            dest_port=pending.server_port,
            transport="tcp",
            application=pending.application,
            external_flow_id=None,
            evidence_ref=pending.evidence_ref,
            details=details,
        )


def _protocol(row: Mapping[str, Any], src_port: int | None, dest_port: int | None) -> str | None:
    fields = {
        "ftp": ("ftp.request.command", "ftp.response.code"),
        "http": ("http.authbasic", "http.authorization", "http.response.code"),
        "imap": ("imap.request.command", "imap.response.status"),
        "pop3": ("pop.request.command", "pop.response.indicator"),
        "smtp": ("smtp.req.command", "smtp.response.code", "smtp.auth.username"),
        "telnet": ("telnet.data",),
    }
    for protocol, names in fields.items():
        if any(_value(row, name) is not None for name in names):
            return protocol
    ports = {src_port, dest_port}
    for port, protocol in {
        21: "ftp",
        23: "telnet",
        25: "smtp",
        80: "http",
        110: "pop3",
        143: "imap",
        587: "smtp",
    }.items():
        if port in ports:
            return protocol
    return None


def _orient_endpoints(
    protocol: str,
    src_ip: str,
    src_port: int | None,
    dest_ip: str,
    dest_port: int | None,
) -> tuple[str, int | None, str, int | None]:
    server_ports = {
        "ftp": {21},
        "telnet": {23},
        "smtp": {25, 587},
        "http": {80, 8080},
        "pop3": {110},
        "imap": {143},
    }.get(protocol, set())
    if src_port in server_ports:
        return dest_ip, dest_port, src_ip, src_port
    return src_ip, src_port, dest_ip, dest_port


def _http_credentials(row: Mapping[str, Any]) -> tuple[str, str] | None:
    decoded = _value(row, "http.authbasic")
    if decoded and ":" in decoded:
        username, password = decoded.split(":", 1)
        return username[:MAX_CREDENTIAL_LENGTH], password[:MAX_CREDENTIAL_LENGTH]
    return None


def _value(row: Mapping[str, Any], key: str) -> str | None:
    raw = row.get(key)
    if raw is None:
        return None
    value = str(raw).strip()
    return value[:MAX_CREDENTIAL_LENGTH] if value and value != "-" else None


def _int_value(row: Mapping[str, Any], key: str) -> int | None:
    value = _value(row, key)
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def _conversation_key(
    src_ip: str, src_port: int | None, dest_ip: str, dest_port: int | None
) -> str:
    endpoints = sorted(((src_ip, src_port or 0), (dest_ip, dest_port or 0)))
    return repr(endpoints)
