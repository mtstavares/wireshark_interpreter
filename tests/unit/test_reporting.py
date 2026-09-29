from backend.app.domain.findings import AssertionStatus, FindingEvidence, Severity
from backend.app.domain.network import ServiceInventory
from backend.app.domain.reports import ReportActivity, ReportFinding
from backend.app.reporting.html import _activity_card, _finding_card, _service_summary


def test_html_finding_escapes_untrusted_content() -> None:
    finding = ReportFinding(
        id="finding",
        title="<script>alert(1)</script>",
        category="signature-alert",
        severity=Severity.HIGH,
        confidence=0.9,
        assertion_status=AssertionStatus.SIGNATURE_MATCH,
        summary="payload & assinatura",
        first_seen=None,
        last_seen=None,
        source_ip=None,
        destination_ip=None,
        destination_port=None,
        evidence=[
            FindingEvidence(kind="event", reference="<img src=x>", source="suricata")
        ],
        mitigations=["validar <contexto>"],
        mitre_attack=[],
        detector_name="test",
        detector_version="1",
        wireshark_filter='http.host == "<host>"',
    )

    rendered = _finding_card(finding)

    assert "<script>" not in rendered
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
    assert "payload &amp; assinatura" in rendered
    assert "&lt;img src=x&gt;" in rendered
    assert "&lt;contexto&gt;" in rendered


def test_html_activity_is_readable_and_escapes_untrusted_content() -> None:
    activity = ReportActivity(
        occurred_at=None,
        finding_id="finding",
        severity=Severity.HIGH,
        assertion_status=AssertionStatus.INFERRED,
        statement="O IP <origem> realizou uma varredura & teste.",
        source_ip="<origem>",
        destination_ip="10.0.0.10",
        destination_port=22,
        confidence=0.9,
        evidence_refs=["<packet:1>"],
    )

    rendered = _activity_card(activity)

    assert "O IP &lt;origem&gt; realizou uma varredura &amp; teste." in rendered
    assert "10.0.0.10:22" in rendered
    assert "&lt;packet:1&gt;" in rendered


def test_html_service_summary_groups_and_limits_rows() -> None:
    services = [
        ServiceInventory("10.0.0.10", 443, "tcp", "https", 8),
        ServiceInventory("10.0.0.11", 443, "tcp", "https", 5),
        ServiceInventory("10.0.0.12", 53, "udp", "dns", 2),
    ]

    rendered = _service_summary(services, limit=1)

    assert "<td>https</td>" in rendered
    assert "<td>443/tcp</td>" in rendered
    assert "<td>2</td><td>13</td>" in rendered
    assert "1 grupo(s) adicional(is) omitido(s)" in rendered
    assert "<td>dns</td>" not in rendered
