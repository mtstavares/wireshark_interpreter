from pathlib import Path

from backend.app.evaluation.corpus import evaluate_corpus, read_pcap_flows

CORPUS = Path("samples/corpus")


def test_corpus_pcaps_are_readable_and_categorized() -> None:
    assert len(read_pcap_flows(CORPUS / "benign-https.pcap")) == 5
    assert len(read_pcap_flows(CORPUS / "malicious-horizontal-scan.pcap")) == 10
    assert len(read_pcap_flows(CORPUS / "malicious-vertical-scan.pcap")) == 15
    assert len(read_pcap_flows(CORPUS / "malicious-telnet.pcap")) == 1


def test_detector_regression_metrics_have_no_known_errors() -> None:
    metrics = evaluate_corpus(CORPUS)

    assert metrics.true_positive == 4
    assert metrics.false_positive == 1
    assert metrics.false_negative == 0
    assert metrics.precision == 0.8
    assert metrics.recall == 1.0
