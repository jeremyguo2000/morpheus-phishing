"""A harder synthetic corpus than the PoC generator, written as .eml files.

The PoC's phishing emails were trivially separable (misspelled domains AND
"URGENT" AND many recipients, every time). A detector can score 100% on that
and still be useless. This generator mixes in the cases that actually hurt:

  hard phish   polite, no urgency words, legitimate-looking domain, but a
               link whose text and href disagree, or a failed DMARC
  hard ham     legitimate IT mail that SAYS "reset your password" and
               "within 24 hours", from a domain that passes DMARC

It is still synthetic. Its job is to exercise every code path and make the
evaluation table non-trivial, not to estimate real-world accuracy.
"""

from __future__ import annotations

import random
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from datetime import datetime, timezone
from pathlib import Path

NAMES = ["Wei Ling Tan", "Arjun Nair", "Siti Rahman", "Daniel Lim", "Mei Chen", "Ravi Kumar", "Sarah Ong"]
COMPANY = "example-corp.com"
AUTHSERV = "mx.example-corp.com"


def _auth(spf: str, dkim: str, dmarc: str) -> str:
    return f"{AUTHSERV}; spf={spf} smtp.mailfrom=x; dkim={dkim} header.d=x; dmarc={dmarc} header.from=x"


def _base(rng: random.Random, sender: str, display: str, subject: str, auth: str) -> EmailMessage:
    msg = EmailMessage()
    msg["Authentication-Results"] = auth
    msg["From"] = f"{display} <{sender}>"
    msg["To"] = f"{rng.choice(NAMES).lower().replace(' ', '.')}@{COMPANY}"
    msg["Subject"] = subject
    msg["Date"] = format_datetime(datetime.now(timezone.utc))
    msg["Message-ID"] = make_msgid(domain="synthetic.invalid")
    return msg


def ham(rng: random.Random) -> EmailMessage:
    kind = rng.random()
    name = rng.choice(NAMES)
    sender = f"{name.split()[0].lower()}@{COMPANY}"
    if kind < 0.3:  # hard ham: legit IT notice full of "phishy" words
        msg = _base(rng, f"it-helpdesk@{COMPANY}", "IT Helpdesk", "Action required: password expiry",
                    _auth("pass", "pass", "pass"))
        msg.set_content("Hi,\n\nYour password expires within 24 hours. Please reset your password through "
                        f"the usual portal at https://sso.{COMPANY}/reset as described in the IT handbook.\n\n"
                        "IT Helpdesk")
        return msg
    msg = _base(rng, sender, name, rng.choice(["Q3 planning notes", "Lunch Thursday?", "Re: vendor contract",
                                               "Slides for Monday", "Invoice 20931 approved"]),
                _auth("pass", "pass", "pass"))
    body = rng.choice(["Hi all,\n\nNotes from today are in the shared folder. Shout if anything is missing.\n",
                       "Thanks, approved on my side. Finance will process it this week.\n",
                       "Can we move the sync to 3pm? I have a clash.\n"])
    msg.set_content(body + f"\n{name}")
    if rng.random() < 0.4:  # some legit HTML mail with honest links
        msg.add_alternative(f"<p>{body}</p><p><a href='https://docs.{COMPANY}/q3'>docs.{COMPANY}/q3</a></p>",
                            subtype="html")
    return msg


def phish(rng: random.Random) -> EmailMessage:
    kind = rng.random()
    if kind < 0.35:  # classic: lookalike domain + urgency (what the PoC generated)
        msg = _base(rng, "security@paypa1-secure.com", "PayPal Security",
                    "URGENT: verify your account within 24 hours", _auth("fail", "none", "fail"))
        msg.set_content("Dear customer,\n\nUnusual sign-in activity was detected. Verify your account within "
                        "24 hours or access will be suspended:\nhttps://paypa1-secure.com/verify\n")
        return msg
    if kind < 0.7:  # hard: polite, HTML-only, link text/href mismatch, passes SPF on attacker's own domain
        msg = _base(rng, "billing@invoices-portal.net", "Accounts Payable", "Updated remittance details",
                    _auth("pass", "pass", "pass"))
        msg.set_content(
            "<p>Hello,</p><p>Please find the updated remittance details for this month's invoice "
            f"<a href='https://invoices-portal.net/view?id={rng.randint(1000, 9999)}'>"
            f"https://docs.{COMPANY}/finance/remittance</a>.</p><p>Kind regards,<br>Accounts</p>",
            subtype="html")
        return msg
    # hard: spoofed internal sender, DMARC fails, reply-to goes elsewhere, no urgency at all
    name = rng.choice(NAMES)
    msg = _base(rng, f"{name.split()[0].lower()}@{COMPANY}", name, "Quick favour",
                _auth("softfail", "none", "fail"))
    msg["Reply-To"] = f"{name.split()[0].lower()}.{rng.randint(10, 99)}@gmail.com"
    msg.set_content("Hi, are you at your desk? I need you to handle something for me today. Reply when free.\n")
    return msg


def write_corpus(out_dir: str | Path, n: int = 200, phishing_rate: float = 0.3, seed: int = 7) -> tuple[int, int]:
    rng = random.Random(seed)
    root = Path(out_dir)
    (root / "phish").mkdir(parents=True, exist_ok=True)
    (root / "ham").mkdir(parents=True, exist_ok=True)
    counts = [0, 0]
    for i in range(n):
        is_phish = rng.random() < phishing_rate
        msg = phish(rng) if is_phish else ham(rng)
        (root / ("phish" if is_phish else "ham") / f"{i:05d}.eml").write_bytes(bytes(msg))
        counts[0 if is_phish else 1] += 1
    return counts[0], counts[1]
