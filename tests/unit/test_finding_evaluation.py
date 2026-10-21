from backend.app.domain.findings import AssertionStatus, Finding, Severity
from backend.app.evaluation.findings import FindingExpectation, evaluate_findings


def _finding(index: int, detector: str, title: str) -> Finding:
    return Finding(
        id=str(index),
        analysis_id="analysis",
        title=title,
        category="test",
        severity=Severity.MEDIUM,
        confidence=0.9,
        assertion_status=AssertionStatus.INFERRED,
        summary="test",
        first_seen=None,
        last_seen=None,
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        destination_port=80,
        evidence=[],
        mitigations=[],
        mitre_attack=[],
        detector_name=detector,
        detector_version="test",
    )


def test_evaluates_true_false_positive_and_false_negative_per_detector() -> None:
    findings = [
        _finding(1, "web", "SQL injection observed"),
        _finding(2, "unexpected", "Unexpected finding"),
    ]
    expectations = [
        FindingExpectation("web", "SQL injection"),
        FindingExpectation("dns", "DNS tunneling"),
    ]

    result = evaluate_findings(findings, expectations)

    assert (result.true_positive, result.false_positive, result.false_negative) == (1, 1, 1)
    assert result.precision == 0.5
    assert result.recall == 0.5
    assert result.unexpected_findings == ["unexpected: Unexpected finding"]
    assert result.missing_expectations == ["dns: DNS tunneling"]
    assert {metric.detector for metric in result.detectors} == {"dns", "unexpected", "web"}
