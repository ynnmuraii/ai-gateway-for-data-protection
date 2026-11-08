"""The evaluation labels must be reproducible, exact, and split before inference."""

import importlib.util
from collections import Counter
from pathlib import Path

from gateway.detection import CATEGORIES, Finding

spec = importlib.util.spec_from_file_location(
    "evaluate_detectors", Path(__file__).parents[2] / "scripts/evaluate-detectors.py"
)
evaluation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluation)


def test_corpus_counts_exact_labels_and_disjoint_partitions():
    corpus = evaluation.build_corpus()
    assert corpus == evaluation.build_corpus()
    assert len({sample["id"] for sample in corpus}) == 4200
    counts = Counter((sample["category"], sample["positive"], sample["split"]) for sample in corpus)
    for category in CATEGORIES:
        for positive in (True, False):
            assert counts[category, positive, "tuning"] == 100
            assert counts[category, positive, "heldout"] == 200
    texts = {
        split: {sample["text"] for sample in corpus if sample["split"] == split}
        for split in ("tuning", "heldout")
    }
    assert not texts["tuning"] & texts["heldout"]
    for sample in corpus:
        assert bool(sample["labels"]) == sample["positive"]
        for label in sample["labels"]:
            assert label["category"] == sample["category"]
            assert 0 <= label["start"] < label["end"] <= len(sample["text"])
            assert sample["text"][label["start"] : label["end"]]


def test_exact_span_scoring_counts_cross_category_false_positives_and_missed_entity():
    class WrongDetector:
        def analyze(self, messages, dictionaries):
            return [Finding(0, 0, 1, "PHONE", 1, "fake")]

    samples = [
        {
            "id": "one",
            "category": "EMAIL",
            "positive": True,
            "split": "heldout",
            "family": "test",
            "text": "x@example.com",
            "labels": [{"category": "EMAIL", "start": 0, "end": 13}],
        }
    ]
    metrics, mismatches = evaluation.evaluate(WrongDetector(), samples)
    assert metrics["heldout"]["EMAIL"]["fn"] == 1
    assert metrics["heldout"]["PHONE"]["fp"] == 1
    assert len(mismatches) == 1 and "text" not in mismatches[0]


def test_expanded_span_still_fails_strict_gate_but_covers_sensitive_value():
    class ExpandedDetector:
        def analyze(self, messages, dictionaries):
            return [Finding(0, 0, 14, "EMAIL", 1, "fake")]

    samples = [
        {
            "id": "one",
            "category": "EMAIL",
            "positive": True,
            "split": "heldout",
            "family": "test",
            "text": "=x@example.com",
            "labels": [{"category": "EMAIL", "start": 1, "end": 14}],
        }
    ]
    metrics, _ = evaluation.evaluate(ExpandedDetector(), samples)
    row = metrics["heldout"]["EMAIL"]
    assert row["tp"] == 0 and row["fp"] == row["fn"] == 1
    assert row["sensitive_value_coverage"] == 1 and row["boundary_expansions"] == 1
