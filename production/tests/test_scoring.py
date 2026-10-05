from __future__ import annotations

import pytest
from conftest import load

from phishguard.decision import Policy
from phishguard.schema import Action, AuthResults, EmailEvent
from phishguard.scoring import RuleEngine, combine
from phishguard.scoring.rules import Signal, registrable_domain


def names(signals):
    return {s.name for s in signals}


@pytest.fixture
def rules():
    return RuleEngine(("paypal.com", "example-corp.com", "dbs.com.sg"))


def test_registrable_domain():
    assert registrable_domain("mail.login.paypal.com") == "paypal.com"
    assert registrable_domain("www.dbs.com.sg") == "dbs.com.sg"
    assert registrable_domain(None) == ""


@pytest.mark.parametrize("host,expected_weight", [
    ("paypa1-secure.com", 0.6),   # homoglyph inside a hyphenated label
    ("paypa1.com", 0.6),
    ("paypall.com", 0.4),         # one edit
    ("paypal-secure.com", 0.35),  # embeds the brand
    ("paypal.com.account-check.example", 0.5),  # brand as a subdomain
    ("dbs-sg.com", None),          # 3-char labels are skipped: too many false positives
    ("paypal.com", None),          # the real thing
    ("login.paypal.com", None),
    ("example.org", None),
])
def test_lookalike(rules, host, expected_weight):
    hit = rules._lookalike(host)
    assert (hit[0] if hit else None) == expected_weight


def test_html_phish_fires_expected_rules(rules):
    found = names(rules.evaluate(load("html_only_phish.eml")))
    assert {"dmarc_fail", "spf_fail", "reply_to_mismatch", "link_text_mismatch",
            "ip_literal_link", "lookalike_sender_domain", "lookalike_link_domain"} <= found


def test_linked_filename_is_not_a_link_mismatch(rules):
    from phishguard.schema import Link
    e = load("ham_multipart_comma_names.eml")
    e.links = [Link(href="https://drive.google.com/file/d/1", href_domain="drive.google.com",
                    display_text="invoice.pdf", text_domain=None)]
    assert "link_text_mismatch" not in names(rules.evaluate(e))


def test_legit_mail_fires_nothing(rules):
    assert rules.evaluate(load("ham_multipart_comma_names.eml")) == []


def test_display_name_spoof_and_attachment(rules):
    assert "display_name_spoof" in names(rules.evaluate(load("forged_auth_header.eml")))
    signals = rules.evaluate(load("attachment_double_ext.eml"))
    att = next(s for s in signals if s.name == "risky_attachment")
    assert att.weight == 0.6 and "double-extension" in att.detail


def test_noisy_or_is_bounded_and_monotonic():
    s1, _ = combine([Signal("a", 0.5, "")], None, "m")
    s2, _ = combine([Signal("a", 0.5, ""), Signal("b", 0.5, "")], None, "m")
    s3, _ = combine([Signal(str(i), 0.9, "") for i in range(20)], 1.0, "m")
    assert s1 == 0.5 and s2 == 0.75 and 0.99 < s3 <= 1.0


def test_reasons_sorted_strongest_first():
    _, reasons = combine([Signal("weak", 0.1, ""), Signal("strong", 0.6, "")], 0.5, "m")
    assert [r.signal for r in reasons] == ["strong", "text_model", "weak"]


def _event(domain="example-corp.com", dmarc=None, trusted=False):
    return EmailEvent(message_id="<x>", received_at=0, raw_ref=None, raw_sha256="0", raw_size=0,
                      from_domain=domain, auth=AuthResults(dmarc=dmarc, trusted=trusted))


@pytest.mark.parametrize("score,action", [(0.1, Action.ALLOW), (0.5, Action.TAG), (0.85, Action.QUARANTINE)])
def test_policy_thresholds(score, action):
    v = Policy(0.5, 0.85).decide(_event("other.com"), score, [], model_name="m", model_version="1",
                                 model_score=None)
    assert v.action is action


def test_allowlist_requires_trusted_dmarc_pass():
    policy = Policy(0.5, 0.85, ("example-corp.com",))
    kw = dict(model_name="m", model_version="1", model_score=None)
    assert policy.decide(_event(dmarc="pass", trusted=True), 0.9, [], **kw).action is Action.ALLOW
    # Spoofed allowlisted sender: forged/untrusted pass, or a fail, must NOT bypass.
    assert policy.decide(_event(dmarc="pass", trusted=False), 0.9, [], **kw).action is Action.QUARANTINE
    assert policy.decide(_event(dmarc="fail", trusted=True), 0.9, [], **kw).action is Action.QUARANTINE


def test_policy_rejects_inverted_thresholds():
    with pytest.raises(ValueError):
        Policy(0.9, 0.5)


def test_pipeline_end_to_end(pipeline):
    phish, ham = pipeline.score([load("html_only_phish.eml"), load("ham_multipart_comma_names.eml")])
    assert phish.action is Action.QUARANTINE and phish.reasons[0].weight >= 0.6
    assert ham.action is Action.ALLOW and ham.score < 0.1
