"""How do we know it works? Join ground truth with scores and measure.

The PoC attached `is_phishing` ground truth to synthetic emails but nothing ever
compared it with the model output. This module does that, at many thresholds,
because "what threshold?" is a business decision you make by looking at the
precision/recall trade-off, not a constant you pick up front.

Two input modes:
  * --labels labels.jsonl --verdicts verdicts.jsonl
        labels:   {"message_id": "...", "is_phishing": true}
        verdicts: Verdict JSON as written to the verdict topic
  * --eml-dir DIR   with DIR/phish/*.eml and DIR/ham/*.eml, scored locally

Caveat to say out loud in an interview: numbers on synthetic data say the
plumbing works. They say nothing about real-world accuracy. You need a
held-out set of real, labelled mail (or public corpora as a starting point),
and you need to keep measuring because phishing changes.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from .parsing import parse_email
from .pipeline import Pipeline

DEFAULT_THRESHOLDS = (0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95)


@dataclass
class Row:
    threshold: float
    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else float("nan")

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else float("nan")

    @property
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else float("nan")

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p == p and r == r and p + r else float("nan")


@dataclass
class Report:
    n: int
    positives: int
    missing_scores: int
    missing_labels: int
    rows: list[Row]

    def format(self) -> str:
        lines = [
            f"joined examples : {self.n}  (phishing: {self.positives}, legit: {self.n - self.positives})",
            f"unscored labels : {self.missing_scores}   unlabelled scores: {self.missing_labels}",
            "",
            f"{'threshold':>9} {'precision':>9} {'recall':>7} {'FPR':>7} {'F1':>6} {'TP':>5} {'FP':>5} {'FN':>5} {'TN':>5}",
        ]
        for r in self.rows:
            lines.append(f"{r.threshold:>9.2f} {r.precision:>9.3f} {r.recall:>7.3f} {r.fpr:>7.3f} {r.f1:>6.3f} "
                         f"{r.tp:>5} {r.fp:>5} {r.fn:>5} {r.tn:>5}")
        return "\n".join(lines)


def evaluate(labels: dict[str, bool], scores: dict[str, float],
             thresholds: tuple[float, ...] = DEFAULT_THRESHOLDS) -> Report:
    joined = [(labels[k], scores[k]) for k in labels.keys() & scores.keys()]
    rows = []
    for t in thresholds:
        tp = sum(1 for y, s in joined if y and s >= t)
        fp = sum(1 for y, s in joined if not y and s >= t)
        fn = sum(1 for y, s in joined if y and s < t)
        tn = sum(1 for y, s in joined if not y and s < t)
        rows.append(Row(t, tp, fp, fn, tn))
    return Report(n=len(joined), positives=sum(1 for y, _ in joined if y),
                  missing_scores=len(labels.keys() - scores.keys()),
                  missing_labels=len(scores.keys() - labels.keys()), rows=rows)


def load_jsonl(path: str | Path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def from_files(labels_path: str, verdicts_path: str) -> tuple[dict[str, bool], dict[str, float]]:
    labels = {r["message_id"]: bool(r["is_phishing"]) for r in load_jsonl(labels_path)}
    scores: dict[str, float] = {}
    for v in load_jsonl(verdicts_path):
        # Duplicates are expected (at-least-once). Same input -> same score, so last write wins.
        scores[v["message_id"]] = float(v["score"])
    return labels, scores


def from_eml_dir(root: str | Path, pipeline: Pipeline, *, model_only: bool = False,
                 trusted_authserv_ids: tuple[str, ...] = ()) -> tuple[dict[str, bool], dict[str, float]]:
    """Parse with the same trust settings as production, or the allowlist and auth paths
    behave differently in evaluation than in the real pipeline."""
    labels: dict[str, bool] = {}
    scores: dict[str, float] = {}
    for label_dir, is_phish in (("phish", True), ("ham", False)):
        files = sorted(Path(root, label_dir).glob("*.eml"))
        events = [parse_email(p.read_bytes(), received_at=time.time(), trusted_authserv_ids=trusted_authserv_ids)
                  for p in files]
        for p, e in zip(files, events):
            e.message_id = f"{label_dir}/{p.name}"  # file path is the stable key here
        for e, v in zip(events, pipeline.score(events)):
            labels[e.message_id] = is_phish
            scores[e.message_id] = float(v.model_score or 0.0) if model_only else v.score
    return labels, scores
