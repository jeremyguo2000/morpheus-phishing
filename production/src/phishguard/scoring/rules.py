"""Deterministic phishing signals, each with a weight and a human-readable reason.

The weights are hand-set starting points, NOT learned values. In production you
would fit them (e.g. logistic regression over these signals + the model score)
on labelled data, and re-check them whenever the evaluation numbers move.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..schema import EmailEvent

# Second-level public suffixes we care about. A real deployment uses the Public
# Suffix List (e.g. the `tldextract` package); this keeps the reference dependency-free.
_MULTI_PART_SUFFIXES = {"com.sg", "edu.sg", "gov.sg", "org.sg", "co.uk", "org.uk", "ac.uk",
                        "com.au", "co.jp", "co.in", "com.hk", "com.my", "co.nz"}

_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "@": "a", "$": "s"})

_RISKY_EXTENSIONS = {"exe", "scr", "js", "jse", "vbs", "vbe", "wsf", "hta", "bat", "cmd", "ps1", "lnk",
                     "iso", "img", "vhd", "html", "htm", "shtml", "svg", "docm", "xlsm", "pptm", "one", "jar"}


@dataclass(frozen=True)
class Signal:
    name: str
    weight: float   # 0..1: how strongly this signal alone suggests phishing
    detail: str


def registrable_domain(host: str | None) -> str:
    """'mail.login.paypal.com' -> 'paypal.com'; 'www.dbs.com.sg' -> 'dbs.com.sg'."""
    if not host:
        return ""
    labels = host.lower().rstrip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _first_label(domain: str) -> str:
    return domain.split(".", 1)[0]


def _edit_distance_at_most_one(a: str, b: str) -> bool:
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) > len(b):
        a, b = b, a
    i = j = edits = 0
    while i < len(a) and j < len(b):
        if a[i] != b[j]:
            edits += 1
            if edits > 1:
                return False
            if len(a) == len(b):
                i += 1
            j += 1
        else:
            i += 1
            j += 1
    return edits + (len(b) - j) + (len(a) - i) <= 1


class RuleEngine:
    def __init__(self, protected_domains: tuple[str, ...] = ()):
        self.protected = tuple(registrable_domain(d) for d in protected_domains)

    def evaluate(self, event: EmailEvent) -> list[Signal]:
        signals: list[Signal] = []
        signals += self._auth(event)
        signals += self._reply_to(event)
        signals += self._display_name(event)
        signals += self._links(event)
        signals += self._lookalike_sender(event)
        signals += self._attachments(event)
        return signals

    # -- individual rules ----------------------------------------------------

    def _auth(self, e: EmailEvent) -> list[Signal]:
        # Failures count even from an untrusted header (attackers forge passes, not fails).
        out = []
        if e.auth.dmarc == "fail":
            out.append(Signal("dmarc_fail", 0.6, f"DMARC failed for {e.from_domain}"))
        if e.auth.spf == "fail":
            out.append(Signal("spf_fail", 0.3, "SPF hard fail"))
        elif e.auth.spf == "softfail":
            out.append(Signal("spf_softfail", 0.15, "SPF softfail"))
        if e.auth.dkim == "fail":
            out.append(Signal("dkim_fail", 0.25, "DKIM signature failed"))
        return out

    def _reply_to(self, e: EmailEvent) -> list[Signal]:
        if not e.reply_to_addr or not e.from_domain:
            return []
        rt_domain = registrable_domain(e.reply_to_addr.rsplit("@", 1)[1])
        if rt_domain != registrable_domain(e.from_domain):
            return [Signal("reply_to_mismatch", 0.25, f"Reply-To goes to {rt_domain}, From is {e.from_domain}")]
        return []

    def _display_name(self, e: EmailEvent) -> list[Signal]:
        # "support@paypal.com" <attacker@evil.example>
        name = e.from_display.lower()
        if "@" in name:
            claimed = registrable_domain(name.rsplit("@", 1)[1].strip(" >\"'"))
            if claimed and claimed != registrable_domain(e.from_domain):
                return [Signal("display_name_spoof", 0.35,
                               f"display name claims {claimed}, actual sender {e.from_domain}")]
        return []

    def _links(self, e: EmailEvent) -> list[Signal]:
        out: list[Signal] = []
        mismatch = next((l for l in e.links if l.text_domain and l.href_domain
                         and registrable_domain(l.text_domain) != registrable_domain(l.href_domain)), None)
        if mismatch:
            out.append(Signal("link_text_mismatch", 0.55,
                              f"link text shows {mismatch.text_domain} but goes to {mismatch.href_domain}"))
        ip_link = next((l for l in e.links if l.href_domain and l.href_domain.replace(".", "").isdigit()), None)
        if ip_link:
            out.append(Signal("ip_literal_link", 0.3, f"link to bare IP {ip_link.href_domain}"))
        for link in e.links:
            hit = self._lookalike(link.href_domain)
            if hit:
                out.append(Signal("lookalike_link_domain", hit[0], f"link domain {link.href_domain} {hit[1]}"))
                break
        return out

    def _lookalike_sender(self, e: EmailEvent) -> list[Signal]:
        hit = self._lookalike(e.from_domain)
        return [Signal("lookalike_sender_domain", hit[0], f"sender {e.from_domain} {hit[1]}")] if hit else []

    def _attachments(self, e: EmailEvent) -> list[Signal]:
        for att in e.attachments:
            name = (att.filename or "").lower()
            parts = name.rsplit(".", 2)
            ext = parts[-1] if len(parts) > 1 else ""
            if ext in _RISKY_EXTENSIONS:
                double = len(parts) == 3 and len(parts[1]) <= 4
                weight = 0.6 if double else 0.5
                kind = "double-extension " if double else ""
                return [Signal("risky_attachment", weight, f"{kind}attachment {att.filename}")]
        return []

    # -- helpers -------------------------------------------------------------

    def _lookalike(self, host: str | None) -> tuple[float, str] | None:
        """Is `host` impersonating a protected domain without being it?

        Known gaps, worth knowing before an interviewer asks:
          * false positives: one-edit matches hit real words (apple -> apply,
            office -> offices) and brand-embedding hits real companies (office-depot);
            production keeps an allowlist of known-good lookalikes and uses
            domain age / reputation to separate them;
          * misses: Unicode homographs (pаypal with a Cyrillic 'а', which arrives as
            punycode xn--...), and brands split across labels.
        """
        domain = registrable_domain(host)
        if not domain or domain in self.protected:
            return None
        # Brand as a subdomain: paypal.com.account-check.example
        padded = f".{host.lower().rstrip('.')}."
        for target in self.protected:
            if f".{target}." in padded:
                return 0.5, f"puts {target} in a subdomain of {domain}"
        label = _first_label(domain)
        # Check every hyphen-separated piece: "paypa1-secure" must be caught via its "paypa1" piece.
        pieces = label.split("-")
        for target in self.protected:
            t_label = _first_label(target)
            if len(t_label) < 4:
                continue  # short labels produce too many false positives
            for piece in pieces:
                if piece != t_label and piece.translate(_HOMOGLYPHS) == t_label:
                    return 0.6, f"is a character-swap of {target}"
            for piece in pieces:
                if piece != t_label and len(piece) >= 5 and _edit_distance_at_most_one(piece, t_label):
                    return 0.4, f"is one edit away from {target}"
            if t_label in pieces:
                return 0.35, f"embeds '{t_label}' (e.g. {t_label}-secure)"
        return None
