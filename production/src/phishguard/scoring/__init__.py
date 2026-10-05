"""Scoring = deterministic rules + a text model, combined into one explainable score.

Why not just the BERT model, as in the PoC? A body-text classifier cannot see
most of the strongest phishing evidence: failed DMARC, a Reply-To that differs
from From, a link whose visible text says one domain while the href goes to
another, a lookalike sender domain, an executable attachment. Rules capture
those cheaply and explain themselves; the model covers the language ("verify
your account within 24 hours") that rules handle badly.
"""

from .combine import combine
from .rules import RuleEngine, Signal
from .text_model import BaselineKeywordScorer, ScorerUnavailable, TextScorer, build_scorer

__all__ = ["RuleEngine", "Signal", "TextScorer", "BaselineKeywordScorer", "ScorerUnavailable",
           "build_scorer", "combine"]
