from datetime import UTC, datetime, timedelta

from backend.app.detection.detectors import (
    AuthenticationDetector,
    BeaconingDetector,
    CleartextCredentialDetector,
    CleartextProtocolDetector,
    CredentialAuthorizationPolicy,
    CredentialAuthorizationRule,
    DetectorConfig,
    DnsAnomalyDetector,
    LegacySnmpDetector,
    PortScanDetector,
    SignatureAlertDetector,
)
from backend.app.domain.findings import AssertionStatus, DetectionContext, Severity
from backend.app.domain.network import NetworkEvent, NetworkFlow

BASE_TIME = datetime(2025, 1, 1, tzinfo=UTC)


def _flow(
    index: int,
    *,
    seconds: int = 0,
    src_ip: str = "10.0.0.1",
    dest_ip: str = "10.0.0.2",
    dest_port: int = 443,
) -> NetworkFlow:
    start = BASE_TIME + timedelta(seconds=seconds)
    return NetworkFlow(
        id=f"flow-{index}",
        analysis_id="analysis",
        sources=["test"],
        external_ids=[str(index)],
        start_time=start,
        end_time=start + timedelta(milliseconds=10),
        src_ip=src_ip,
        src_port=50_000 + index,
        dest_ip=dest_ip,
        dest_port=dest_port,
        transport="tcp",
        application=None,
        src_bytes=60,
        dest_bytes=0,
        src_packets=1,
        dest_packets=0,
        evidence_refs=[f"packet:{index}"],
    )


def _event(
    index: int,
    *,
    result: str | None = None,
    username: str | None = None,
    seconds: int = 0,
    application: str = "ssh",
    details: dict[str, object] | None = None,
    source: str = "zeek",
    event_type: str = "auth",
) -> NetworkEvent:
    event_details = details or {}
    if result is not None:
        event_details["result"] = result
    if username is not None:
        event_details["username"] = username
    return NetworkEvent(
        id=f"event-{index}",
        analysis_id="analysis",
        source=source,
        event_type=event_type,
        occurred_at=BASE_TIME + timedelta(seconds=seconds),
        src_ip="10.0.0.10",
        src_port=52_000,
        dest_ip="10.0.0.20",
        dest_port=22,
        transport="tcp",
        application=application,
        external_flow_id=None,
        evidence_ref=f"event:{index}",
        details=event_details,
    )


def test_detects_horizontal_and_vertical_scans_but_ignores_benign_volume() -> None:
    config = DetectorConfig(horizontal_scan_hosts=3, vertical_scan_ports=3)
    horizontal = [
        _flow(index, dest_ip=f"10.0.1.{index}", dest_port=445, seconds=index)
        for index in range(1, 4)
    ]
    vertical = [_flow(index + 10, dest_port=port) for index, port in enumerate((21, 22, 23))]

    findings = PortScanDetector(config).detect(
        DetectionContext("analysis", flows=[*horizontal, *vertical])
    )
    benign = PortScanDetector(config).detect(DetectionContext("analysis", flows=horizontal[:2]))

    assert {finding.destination_port for finding in findings} == {None, 445}
    assert all(finding.mitre_attack == ["T1046"] for finding in findings)
    assert benign == []


def test_detects_brute_force_password_spray_and_success_after_failures() -> None:
    failures = [
        _event(index, result="failed", username=f"user-{index}", seconds=index)
        for index in range(5)
    ]
    repeated = [
        _event(index + 10, result="failed", username="admin", seconds=index + 10)
        for index in range(5)
    ]
    success = _event(30, result="success", username="admin", seconds=30)

    findings = AuthenticationDetector(DetectorConfig()).detect(
        DetectionContext("analysis", events=[*failures, *repeated, success])
    )

    assert {finding.title for finding in findings} == {
        "Possível ataque de força bruta",
        "Possível password spraying",
        "Autenticação bem-sucedida após falhas",
    }
    success_finding = next(finding for finding in findings if "bem-sucedida" in finding.title)
    assert success_finding.summary.startswith("O IP 10.0.0.10 teve sucesso ao autenticar via SSH")
    assert "usando o usuário admin" in success_finding.summary
    assert (
        AuthenticationDetector(DetectorConfig()).detect(
            DetectionContext("analysis", events=[success])
        )
        == []
    )


def test_reports_full_cleartext_credentials_and_unauthorized_success() -> None:
    event = _event(
        50,
        result="success",
        username="admin",
        application="ftp",
        source="tshark",
        event_type="authentication",
        details={
            "result": "success",
            "username": "admin",
            "password": "secret-value",
            "credential_transport": "cleartext",
        },
    )
    policy = CredentialAuthorizationPolicy(
        default="deny",
        rules=(
            CredentialAuthorizationRule(
                destination_ip="10.0.0.20",
                service="ftp",
                username="admin",
                source_networks=("10.0.1.0/24",),
            ),
        ),
    )

    finding = CleartextCredentialDetector(policy).detect(
        DetectionContext("analysis", events=[event])
    )[0]

    assert finding.title == "Autenticação não autorizada em texto claro"
    assert finding.severity is Severity.CRITICAL
    assert 'usuário "admin" e a senha "secret-value"' in finding.summary
    assert finding.assertion_status is AssertionStatus.OBSERVED


def test_http_status_does_not_claim_successful_login() -> None:
    event = _event(
        51,
        application="http",
        source="tshark",
        event_type="authentication",
        details={
            "result": "possible",
            "username": "admin",
            "password": "secret-value",
            "http_status": 200,
        },
    )

    finding = CleartextCredentialDetector().detect(DetectionContext("analysis", events=[event]))[0]

    assert "não comprova sucesso" in finding.summary
    assert finding.assertion_status is AssertionStatus.INFERRED


def test_detects_cleartext_protocol_as_observed() -> None:
    finding = CleartextProtocolDetector().detect(
        DetectionContext("analysis", flows=[_flow(1, dest_port=23)])
    )[0]

    assert finding.severity is Severity.HIGH
    assert finding.assertion_status is AssertionStatus.OBSERVED
    assert finding.destination_port == 23


def test_detects_repeated_high_entropy_dns_queries() -> None:
    queries = [
        _event(
            index,
            application="dns",
            event_type="dns",
            details={"query": ("a8F3kP9xQ2zLm7Nw" * 4) + f"{index}.example"},
        )
        for index in range(3)
    ]

    findings = DnsAnomalyDetector(DetectorConfig()).detect(
        DetectionContext("analysis", events=queries)
    )

    assert len(findings) == 1
    assert findings[0].mitre_attack == ["T1071.004"]


def test_detects_periodic_beacon_and_rejects_irregular_intervals() -> None:
    periodic = [_flow(index, seconds=index * 60) for index in range(5)]
    irregular = [
        _flow(index + 10, seconds=seconds) for index, seconds in enumerate((0, 5, 80, 81, 300))
    ]
    detector = BeaconingDetector(DetectorConfig())

    assert len(detector.detect(DetectionContext("analysis", flows=periodic))) == 1
    assert detector.detect(DetectionContext("analysis", flows=irregular)) == []


def test_converts_suricata_alert_into_explainable_finding() -> None:
    alert = _event(
        1,
        source="suricata",
        event_type="alert",
        details={"alert": {"signature": "ET TEST Exploit", "severity": 1}},
    )

    finding = SignatureAlertDetector().detect(DetectionContext("analysis", events=[alert]))[0]

    assert finding.title == "ET TEST Exploit"
    assert finding.severity is Severity.HIGH
    assert finding.assertion_status is AssertionStatus.SIGNATURE_MATCH


def test_detects_legacy_snmp_but_not_snmpv3() -> None:
    legacy = _event(
        1,
        application="snmp",
        event_type="packet",
        details={"snmp_version": 0},
    )
    modern = _event(
        2,
        application="snmp",
        event_type="packet",
        details={"snmp_version": 3},
    )
    legacy = NetworkEvent(
        id=legacy.id,
        analysis_id=legacy.analysis_id,
        source=legacy.source,
        event_type=legacy.event_type,
        occurred_at=legacy.occurred_at,
        src_ip=legacy.src_ip,
        src_port=50_000,
        dest_ip=legacy.dest_ip,
        dest_port=161,
        transport="udp",
        application=legacy.application,
        external_flow_id=None,
        evidence_ref=legacy.evidence_ref,
        details=legacy.details,
    )
    modern = NetworkEvent(
        id=modern.id,
        analysis_id=modern.analysis_id,
        source=modern.source,
        event_type=modern.event_type,
        occurred_at=modern.occurred_at,
        src_ip=modern.src_ip,
        src_port=50_000,
        dest_ip=modern.dest_ip,
        dest_port=161,
        transport="udp",
        application=modern.application,
        external_flow_id=None,
        evidence_ref=modern.evidence_ref,
        details=modern.details,
    )

    findings = LegacySnmpDetector().detect(DetectionContext("analysis", events=[legacy, modern]))

    assert len(findings) == 1
    assert findings[0].title == "Uso observado de versão legada do SNMP"
    assert findings[0].assertion_status is AssertionStatus.OBSERVED
