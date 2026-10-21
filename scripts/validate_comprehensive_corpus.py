from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from backend.app.analyzers.command import TsharkAnalyzer
from backend.app.detection.detectors import default_detectors
from backend.app.domain.analyses import AnalyzerStatus
from backend.app.domain.findings import DetectionContext
from backend.app.evaluation.findings import FindingExpectation, evaluate_findings
from backend.app.normalization.parsers import parse_tshark_directory


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate the comprehensive synthetic PCAP")
    parser.add_argument("--tshark", default=r"C:\Program Files\Wireshark\tshark.exe")
    parser.add_argument("--pcap", default="samples/corpus/comprehensive-attacks.pcap")
    parser.add_argument(
        "--expectations", default="samples/corpus/comprehensive-attacks.expected.json"
    )
    parser.add_argument("--output")
    parser.add_argument("--no-strict", action="store_true")
    args = parser.parse_args()

    capture = Path(args.pcap).resolve()
    analyzer = TsharkAnalyzer(args.tshark)
    with tempfile.TemporaryDirectory(prefix="pcap-corpus-validation-") as temporary:
        output = Path(temporary) / "analysis" / "tshark"
        result = analyzer.analyze(capture, output, timeout_seconds=120)
        if result.status is not AnalyzerStatus.COMPLETED:
            raise SystemExit(result.diagnostic or f"TShark status: {result.status}")
        flows, events = parse_tshark_directory("corpus-validation", output)
        context = DetectionContext(
            analysis_id="corpus-validation",
            flows=flows,
            events=events,
        )
        findings = [
            finding
            for detector in default_detectors()
            for finding in detector.detect(context)
        ]
        expected = json.loads(Path(args.expectations).read_text(encoding="utf-8"))
        expectations = [
            FindingExpectation.from_dict(item) for item in expected["expected_findings"]
        ]
        quality = evaluate_findings(findings, expectations)
        summary = {
            "capture": str(capture),
            "flows": len(flows),
            "security_events": len(events),
            "findings": [
                {
                    "title": finding.title,
                    "category": finding.category,
                    "severity": finding.severity,
                    "summary": finding.summary,
                }
                for finding in findings
            ],
            "compressed_tshark_artifact": any(
                artifact.path == "stdout.log.gz" for artifact in result.artifacts
            ),
            "quality": quality.to_dict(),
        }
        rendered = json.dumps(summary, indent=2, ensure_ascii=False)
        print(rendered)
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(rendered + "\n", encoding="utf-8")
        if not args.no_strict and (quality.false_positive or quality.false_negative):
            raise SystemExit(1)


if __name__ == "__main__":
    main()
