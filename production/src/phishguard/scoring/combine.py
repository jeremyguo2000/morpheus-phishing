"""Combine rule signals and the model score into one number.

Noisy-OR: treat each signal as independent evidence that "would make this
phishing with probability w". Then

    score = 1 - (1 - w_model * p_model) * prod(1 - w_i)

Properties that make it a reasonable starting point:
  * any single strong signal can push the score high on its own;
  * several weak signals add up, but the score never exceeds 1;
  * it is explainable: every factor maps to a Reason in the verdict.

Its weakness is the independence assumption (DMARC fail and SPF fail are
correlated, so it double counts). Once you have labelled data, replace this
with a fitted model (logistic regression over the same signals is the obvious
next step) and calibrate the output so a score of 0.9 really means ~90%.
"""

from __future__ import annotations

from ..schema import Reason
from .rules import Signal

MODEL_TRUST = 0.8  # how much we let the text model alone move the score


def combine(signals: list[Signal], model_score: float | None, model_name: str) -> tuple[float, list[Reason]]:
    keep = 1.0
    reasons: list[Reason] = []
    if model_score is not None:
        w = max(0.0, min(1.0, model_score)) * MODEL_TRUST
        keep *= 1 - w
        reasons.append(Reason("text_model", round(w, 4), f"{model_name} scored {model_score:.3f}"))
    for s in signals:
        keep *= 1 - s.weight
        reasons.append(Reason(s.name, s.weight, s.detail))
    reasons.sort(key=lambda r: r.weight, reverse=True)
    return round(1 - keep, 4), reasons
