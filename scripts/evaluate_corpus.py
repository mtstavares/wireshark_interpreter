from pathlib import Path

from backend.app.evaluation.corpus import evaluate_corpus


def main() -> None:
    metrics = evaluate_corpus(Path("samples/corpus"))
    print(f"TP={metrics.true_positive}")
    print(f"FP={metrics.false_positive}")
    print(f"FN={metrics.false_negative}")
    print(f"precision={metrics.precision:.3f}")
    print(f"recall={metrics.recall:.3f}")


if __name__ == "__main__":
    main()
