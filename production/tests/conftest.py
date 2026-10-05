from __future__ import annotations

import time
from pathlib import Path

import pytest

from phishguard.decision import Policy
from phishguard.parsing import parse_email
from phishguard.pipeline import Pipeline
from phishguard.scoring import BaselineKeywordScorer, RuleEngine

FIXTURES = Path(__file__).parent / "fixtures"
TRUSTED = ("mx.example-corp.com",)


def load(name: str, trusted: tuple[str, ...] = TRUSTED):
    return parse_email((FIXTURES / name).read_bytes(), received_at=time.time(), trusted_authserv_ids=trusted)


@pytest.fixture
def pipeline() -> Pipeline:
    return Pipeline(RuleEngine(("paypal.com", "example-corp.com")), BaselineKeywordScorer(),
                    Policy(0.5, 0.85, ("example-corp.com",)))
