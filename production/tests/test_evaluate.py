from __future__ import annotations

import json
import math

from phishguard.evaluate import evaluate, from_eml_dir, from_files
from phishguard.synthetic import write_corpus


def test_confusion_counts():
    labels = {"a": True, "b": True, "c": False, "d": False, "e": True}
    scores = {"a": 0.9, "b": 0.4, "c": 0.6, "d": 0.1, "x": 0.99}
    report = evaluate(labels, scores, thresholds=(0.5,))
    row = report.rows[0]
    assert (row.tp, row.fp, row.fn, row.tn) == (1, 1, 1, 1)
    assert row.precision == 0.5 and row.recall == 0.5 and row.fpr == 0.5
    assert report.missing_scores == 1 and report.missing_labels == 1


def test_no_predicted_positives_gives_nan_precision_not_crash():
    row = evaluate({"a": True}, {"a": 0.1}, thresholds=(0.5,)).rows[0]
    assert math.isnan(row.precision) and row.recall == 0.0


def test_from_files_dedupes_verdicts(tmp_path):
    (tmp_path / "l.jsonl").write_text(json.dumps({"message_id": "m1", "is_phishing": True}) + "\n")
    (tmp_path / "v.jsonl").write_text("\n".join(json.dumps({"message_id": "m1", "score": s}) for s in (0.7, 0.7)))
    labels, scores = from_files(tmp_path / "l.jsonl", tmp_path / "v.jsonl")
    assert labels == {"m1": True} and scores == {"m1": 0.7}


def test_synthetic_corpus_evaluates(tmp_path, pipeline):
    n_phish, n_ham = write_corpus(tmp_path, n=60, seed=1)
    labels, scores = from_eml_dir(tmp_path, pipeline)
    report = evaluate(labels, scores)
    assert report.n == 60 == n_phish + n_ham and report.positives == n_phish
