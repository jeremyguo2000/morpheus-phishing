from __future__ import annotations

from conftest import FIXTURES, load

from phishguard.parsing import domain_in_text, host_of, parse_auth_results, parse_email
from phishguard.schema import EmailEvent


def test_html_only_email_still_has_text_and_links():
    e = load("html_only_phish.eml")
    assert e.had_html
    assert "Dear customer" in e.text_body
    assert "var x" not in e.text_body and "color:red" not in e.text_body  # script/style dropped
    mismatch = [l for l in e.links if l.text_domain]
    assert mismatch and mismatch[0].href_domain == "paypa1-secure.com"
    assert mismatch[0].text_domain == "paypal.com"
    assert any(l.href_domain == "203.0.113.9" for l in e.links)
    # The decoy URL in the anchor's visible text must not become a "link" to paypal.com.
    assert not any(l.href_domain == "www.paypal.com" for l in e.links)
    assert e.reply_to_addr == "help@collect-desk.ru"


def test_folded_auth_results_from_trusted_mta():
    e = load("html_only_phish.eml")
    assert e.auth.trusted and e.auth.authserv_id == "mx.example-corp.com"
    assert (e.auth.spf, e.auth.dkim, e.auth.dmarc) == ("fail", "none", "fail")


def test_display_names_with_commas_are_one_recipient_each():
    e = load("ham_multipart_comma_names.eml")
    assert e.to == ["john.smith@example-corp.com", "mei@example-corp.com"]
    assert e.cc == ["weiling@example-corp.com"]


def test_encoded_subject_and_multipart_alternative():
    e = load("ham_multipart_comma_names.eml")
    assert e.subject == "Q3 planning – notes"
    assert e.text_body.startswith("Notes are at")           # plain part preferred for text
    assert [l.href for l in e.links] == ["https://docs.example-corp.com/q3"]  # bare URL deduped
    assert e.attachments == []                                # body parts are not attachments


def test_one_passing_dkim_signature_is_enough():
    assert load("ham_multipart_comma_names.eml").auth.dkim == "pass"


def test_attachment_metadata():
    e = load("attachment_double_ext.eml")
    assert len(e.attachments) == 1
    att = e.attachments[0]
    assert att.filename == "invoice.pdf.exe" and att.size > 0 and len(att.sha256) == 64
    assert e.text_body.startswith("Please see the attached invoice")


def test_forged_auth_header_is_ignored_when_trust_is_configured():
    e = load("forged_auth_header.eml")
    assert e.auth.authserv_id == "mx.example-corp.com" and e.auth.dmarc == "fail"
    only_attacker = parse_auth_results(["attacker-relay.example; dmarc=pass"], ("mx.example-corp.com",))
    assert only_attacker.dmarc is None and not only_attacker.trusted


def test_untrusted_auth_is_flagged_when_no_trust_configured():
    e = load("forged_auth_header.eml", trusted=())
    assert not e.auth.trusted
    assert "auth_results_untrusted" in e.parse_warnings


def test_unknown_charset_and_missing_message_id_do_not_crash():
    raw = (FIXTURES / "bad_charset_no_msgid.eml").read_bytes()
    a = parse_email(raw, received_at=0)
    b = parse_email(raw, received_at=1)
    assert "Hello" in a.text_body
    assert any(w.startswith("charset_fallback") for w in a.parse_warnings)
    assert "missing_message_id" in a.parse_warnings
    assert a.message_id.startswith("<sha256-") and a.message_id == b.message_id  # deterministic -> dedupable


def test_garbage_input_never_raises():
    for raw in (b"", b"\x00\xff\xfe garbage", b"From: \r\n\r\n", b"Content-Type: multipart/mixed\r\n\r\n--"):
        e = parse_email(raw, received_at=0)
        assert isinstance(e, EmailEvent)
        # parse_email swallows everything, so "didn't raise" proves nothing on its own:
        # check the fallback path wasn't hit either.
        assert not any(w.startswith("parse_failed") for w in e.parse_warnings), e.parse_warnings


def test_event_json_round_trip():
    e = load("html_only_phish.eml")
    assert EmailEvent.from_json(e.to_json()) == e


def test_host_helpers():
    assert host_of("https://paypal.com@evil.example/login") == "evil.example"  # userinfo trick
    assert host_of("HTTP://Example.COM:8080/x") == "example.com"
    assert host_of("http://[bad") is None
    assert domain_in_text("https://www.paypal.com/signin") == "paypal.com"
    assert domain_in_text("click here") is None
    for not_a_domain in ("invoice.pdf", "Q3-report.xlsx", "19.99", "v2.0", "README.md", "10.0.0.1"):
        assert domain_in_text(not_a_domain) is None, not_a_domain
    assert domain_in_text("docs.example-corp.com/q3") == "docs.example-corp.com"


def test_divergent_html_part_reaches_the_model():
    raw = (b"From: a@b.example\r\nSubject: hi\r\nMIME-Version: 1.0\r\n"
           b"Content-Type: multipart/alternative; boundary=X\r\n\r\n"
           b"--X\r\nContent-Type: text/plain\r\n\r\nLunch Thursday?\r\n"
           b"--X\r\nContent-Type: text/html\r\n\r\n<p>Verify your account within 24 hours or it will be suspended</p>\r\n"
           b"--X--\r\n")
    e = parse_email(raw, received_at=0)
    assert "plain_html_divergent" in e.parse_warnings
    assert "Lunch Thursday" in e.text_body and "Verify your account" in e.text_body


def test_matching_alternatives_are_not_duplicated():
    assert "plain_html_divergent" not in load("ham_multipart_comma_names.eml").parse_warnings


def test_bare_non_text_message_is_an_attachment():
    raw = (b"From: a@b.example\r\nSubject: doc\r\nMIME-Version: 1.0\r\n"
           b"Content-Type: application/octet-stream; name=a.exe\r\nContent-Transfer-Encoding: base64\r\n\r\nTVqQAAMA\r\n")
    e = parse_email(raw, received_at=0)
    assert [a.filename for a in e.attachments] == ["a.exe"]
