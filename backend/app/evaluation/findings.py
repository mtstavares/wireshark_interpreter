from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
from typing import Any

from backend.app.domain.findings import Finding


@dataclass(frozen=True, slots=True)
class FindingExpectation:
    detector: str
    title_contains: str
    count: int = 1
    source_ip: str | None = None
    destination_ip: str | None = None

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> FindingExpectation:
        count = int(value.get("count", 1))
        if count < 1:
            raise ValueError("Expected finding count must be positive")
        return cls(
            detector=str(value["detector"]),
            title_contains=str(value["title_contains"]),
            count=count,
            source_ip=str(value["source_ip"]) if value.get("source_ip") else None,
            destination_ip=(
                str(value["destination_ip"]) if value.get("destination_ip") else None
            ),
        )


@dataclass(frozen=True, slots=True)
class DetectorQualityMetrics:
    detector: str
    true_positive: int
    false_positive: int
    false_negative: int

    @property
    def precision(self) -> float:
        total = self.true_positive + self.false_positive
        return self.true_positive / total if total else 1.0

    @property
    def recall(self) -> float:
        total = self.true_positive + self.false_negative
        return self.true_positive / total if total else 1.0

    def to_dict(self) -> dict[str, str | int | float]:
        return {
            **asdict(self),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
        }


@dataclass(frozen=True, slots=True)
class QualityEvaluation:
    true_positive: int
    false_positive: int
    false_negative: int
    detectors: list[DetectorQualityMetrics]
    unexpected_findings: list[str]
    missing_expectations: list[str]

    @property
    def precision(self) -> float:
        total = self.true_positive + self.false_positive
        return self.true_positive / total if total else 1.0

    @property
    def recall(self) -> float:
        total = self.true_positive + self.false_negative
        return self.true_positive / total if total else 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "false_negative": self.false_negative,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "detectors": [metric.to_dict() for metric in self.detectors],
            "unexpected_findings": self.unexpected_findings,
            "missing_expectations": self.missing_expectations,
        }


def evaluate_findings(
    findings: list[Finding], expectations: list[FindingExpectation]
) -> QualityEvaluation:
    expanded = [expectation for expectation in expectations for _ in range(expectation.count)]
    available = set(range(len(findings)))
    matched_findings: set[int] = set()
    matched_expectations: set[int] = set()

    for expectation_index, expectation in enumerate(expanded):
        match = next(
            (
                finding_index
                for finding_index in sorted(available)
                if _matches(findings[finding_index], expectation)
            ),
            None,
        )
        if match is None:
            continue
        available.remove(match)
        matched_findings.add(match)
        matched_expectations.add(expectation_index)

    counts: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    for index, finding in enumerate(findings):
        counts[finding.detector_name][0 if index in matched_findings else 1] += 1
    for index, expectation in enumerate(expanded):
        if index not in matched_expectations:
            counts[expectation.detector][2] += 1

    metrics = [
        DetectorQualityMetrics(detector, values[0], values[1], values[2])
        for detector, values in sorted(counts.items())
    ]
    unexpected = [
        f"{findings[index].detector_name}: {findings[index].title}"
        for index in sorted(available)
    ]
    missing = [
        f"{expanded[index].detector}: {expanded[index].title_contains}"
        for index in range(len(expanded))
        if index not in matched_expectations
    ]
    return QualityEvaluation(
        true_positive=len(matched_findings),
        false_positive=len(available),
        false_negative=len(expanded) - len(matched_expectations),
        detectors=metrics,
        unexpected_findings=unexpected,
        missing_expectations=missing,
    )


def _matches(finding: Finding, expectation: FindingExpectation) -> bool:
    return (
        finding.detector_name == expectation.detector
        and expectation.title_contains.casefold() in finding.title.casefold()
        and (expectation.source_ip is None or finding.source_ip == expectation.source_ip)
        and (
            expectation.destination_ip is None
            or finding.destination_ip == expectation.destination_ip
        )
    )
