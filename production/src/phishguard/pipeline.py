"""Pure scoring pipeline: EmailEvents -> Verdicts. No Kafka here.

Keeping this free of I/O means the same code path runs in the worker, in the
`phishguard score` CLI, in evaluation, and in unit tests.
"""

from __future__ import annotations

from typing import Sequence

from .decision import Policy
from .schema import EmailEvent, Verdict
from .scoring import RuleEngine, TextScorer, combine


class Pipeline:
    def __init__(self, rules: RuleEngine, scorer: TextScorer, policy: Policy):
        self.rules, self.scorer, self.policy = rules, scorer, policy

    def score(self, events: Sequence[EmailEvent], *, now: float | None = None) -> list[Verdict]:
        """Score a batch. One model call per batch (batching is what makes GPU inference pay off).
        Raises ScorerUnavailable if the model is down; the caller decides whether to retry."""
        texts = [_model_input(e) for e in events]
        model_scores = self.scorer.score_batch(texts)
        verdicts = []
        for event, model_score in zip(events, model_scores, strict=True):
            signals = self.rules.evaluate(event)
            score, reasons = combine(signals, model_score, self.scorer.name)
            verdicts.append(self.policy.decide(event, score, reasons, model_name=self.scorer.name,
                                               model_version=self.scorer.version, model_score=model_score,
                                               now=now))
        return verdicts


def _model_input(event: EmailEvent) -> str:
    # Subject carries a lot of the phishing language and the PoC never sent it to the model.
    return f"{event.subject}\n\n{event.text_body}".strip()
