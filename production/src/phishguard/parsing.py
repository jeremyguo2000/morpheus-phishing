"""Raw RFC 5322 bytes -> EmailEvent.

What changed from the PoC parser (`email_to_kafka.py::parse_email`) and why:

1. Bytes in, not str. Reading stdin as text forces a decode before the MIME
   parser has seen the charset declarations. `BytesParser` lets each part be
   decoded with its own declared charset.
2. `policy.default` instead of the legacy compat32 API: decoded headers, real
   address objects, and `get_body()` which understands multipart/alternative.
3. Addresses via the parser, not `split(',')`. `"Smith, John" <j@x.com>` is ONE
   recipient; the PoC counted it as zero or two depending on the line.
4. HTML is not dropped. Most phishing is HTML-only. The PoC read only text/plain
   parts, so an HTML-only phish reached the model as an empty string. And when
   both parts exist but say different things (a harmless plain part, a
   phishing HTML part: what the recipient actually sees), both go to the model.
5. Links are extracted with BOTH the href and the visible text, because "text
   says paypal.com, href goes to paypa1-secure.com" is one of the strongest
   phishing signals and is invisible once you flatten HTML to text.
6. Authentication-Results (SPF/DKIM/DMARC) are extracted, but only trusted when
   they carry our own MTA's authserv-id. Anyone can put a fake "dmarc=pass"
   header in an email. This check is only as good as the MTA: RFC 8601 §5
   requires it to REMOVE incoming headers that claim its authserv-id, and every
   path into the pipeline must go through that MTA. Verify both before you rely
   on `trusted`, because the allowlist in decision.py depends on it.
7. The function never raises. A malformed email is still evidence; it becomes an
   event with `parse_warnings`, not a crash or a lost message.
"""

from __future__ import annotations

import hashlib
import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser
from urllib.parse import urlsplit

from .schema import Attachment, AuthResults, EmailEvent, Link

MAX_TEXT_CHARS = 200_000   # cap what we hand to tokenizers/regexes; huge bodies are a DoS vector
MAX_LINKS = 200

_URL_RE = re.compile(r"""https?://[^\s<>"'()\[\]{}]+""", re.IGNORECASE)
_DOMAINISH_RE = re.compile(r"^(https?://)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)\.?(?:[/:?#]\S*)?$", re.IGNORECASE)
# Link text like "invoice.pdf" or "report.xlsx" is a filename, not a domain. A few of
# these are real TLDs (.zip, .mov, .md); we accept missing those bare-text cases
# rather than flag every linked attachment name.
_FILE_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "zip", "rar", "7z",
                    "md", "png", "jpg", "jpeg", "gif", "svg", "html", "htm", "eml", "msg", "json", "xml",
                    "mp3", "mp4", "mov", "exe", "iso", "py", "js", "ts", "log", "ics", "vcf"}
_AUTH_METHOD_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
_BLOCK_TAGS = {"br", "p", "div", "tr", "li", "h1", "h2", "h3", "h4", "table"}


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

class _HTMLExtractor(HTMLParser):
    """Collects visible text and (href, anchor text) pairs. Stdlib only."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.anchors: list[tuple[str, str]] = []
        self._skip_depth = 0
        self._open_anchor: tuple[str, list[str]] | None = None

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip_depth += 1
        elif tag == "a":
            href = dict(attrs).get("href")
            self._open_anchor = (href, []) if href else None
        if tag in _BLOCK_TAGS:
            self.text.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip_depth:
            self._skip_depth -= 1
        elif tag == "a" and self._open_anchor:
            href, parts = self._open_anchor
            self.anchors.append((href.strip(), " ".join("".join(parts).split())))
            self._open_anchor = None

    def handle_data(self, data):
        if self._skip_depth:
            return
        self.text.append(data)
        if self._open_anchor:
            self._open_anchor[1].append(data)


def html_to_text(html: str) -> tuple[str, list[tuple[str, str]]]:
    extractor = _HTMLExtractor()
    try:
        extractor.feed(html)
        extractor.close()
    except Exception:  # HTMLParser is lenient, but never let markup kill the pipeline
        pass
    text = re.sub(r"[ \t\r\f\v]+", " ", "".join(extractor.text))
    text = re.sub(r"\n\s*\n+", "\n\n", text).strip()
    return text, extractor.anchors


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def host_of(url: str) -> str | None:
    """Hostname of a URL, lowercased. Handles the userinfo trick:
    https://paypal.com@evil.example/ -> evil.example"""
    try:
        host = urlsplit(url.strip()).hostname
    except ValueError:
        return None
    return host.rstrip(".").lower() if host else None


def domain_in_text(text: str) -> str | None:
    """If visible link text *looks like* a URL or domain, return that domain.
    'https://www.paypal.com/signin' -> 'paypal.com'; 'invoice.pdf', '19.99', 'v2.0' -> None."""
    match = _DOMAINISH_RE.match(text.strip())
    if not match:
        return None
    has_scheme, domain = bool(match.group(1)), match.group(2).lower()
    tld = domain.rsplit(".", 1)[-1]
    if not (tld.isalpha() and 2 <= len(tld) <= 24):
        return None  # numbers and versions: 19.99, v2.0, 10.0.0.1 (IP links are a separate rule)
    if not has_scheme and tld in _FILE_EXTENSIONS:
        return None
    return domain


def _diverges(plain: str, html_text: str) -> bool:
    """Do the plain and HTML alternatives say materially different things?"""
    a, b = set(re.findall(r"\w{3,}", plain.lower())), set(re.findall(r"\w{3,}", html_text.lower()))
    if not a or not b:
        return bool(a) != bool(b)
    return len(a & b) / len(a | b) < 0.5


def _safe_text(part: EmailMessage, warnings: list[str]) -> str:
    try:
        return part.get_content()
    except (LookupError, UnicodeError, AssertionError, KeyError) as exc:
        # Unknown/bogus charset. Fall back to bytes decoded as UTF-8 with replacement.
        warnings.append(f"charset_fallback:{type(exc).__name__}")
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def _addresses(msg: EmailMessage, name: str, warnings: list[str]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    try:
        for header in msg.get_all(name, []) or []:
            addrs = getattr(header, "addresses", None)
            if addrs is not None:
                pairs.extend((a.display_name, a.addr_spec) for a in addrs)
            else:
                pairs.extend(getaddresses([str(header)]))
    except Exception as exc:
        warnings.append(f"bad_address_header:{name}:{type(exc).__name__}")
    return [(display, addr.lower()) for display, addr in pairs if "@" in addr]


def parse_auth_results(values: list[str], trusted_ids: tuple[str, ...]) -> AuthResults:
    """Parse RFC 8601 Authentication-Results.

    Header format: "<authserv-id> [version]; method=result prop=value; ..."
    If `trusted_ids` is configured, only a header whose authserv-id is one of
    ours is used. Otherwise we take the topmost (most recently added) header and
    mark the result untrusted, which downstream rules treat with suspicion.
    """
    candidates: list[tuple[str, str]] = []
    for value in values:
        flat = " ".join(str(value).split())
        if not flat:
            continue
        authserv_id = flat.split(";", 1)[0].strip().split(" ")[0].lower()
        candidates.append((authserv_id, flat))

    chosen: tuple[str, str] | None = None
    trusted = False
    if trusted_ids:
        chosen = next(((a, v) for a, v in candidates if a in trusted_ids), None)
        trusted = chosen is not None
    elif candidates:
        chosen = candidates[0]
    if chosen is None:
        return AuthResults()

    found: dict[str, list[str]] = {}
    for method, result in _AUTH_METHOD_RE.findall(chosen[1]):
        found.setdefault(method.lower(), []).append(result.lower())

    def pick(method: str) -> str | None:
        results = found.get(method)
        if not results:
            return None
        # Multiple DKIM signatures are normal (e.g. sender + mailing-list relay); any valid one
        # counts as a DKIM pass. Whether the signing domain *aligns* with From is DMARC's job,
        # so rules that care about alignment should look at the dmarc result.
        return "pass" if "pass" in results else results[0]

    return AuthResults(spf=pick("spf"), dkim=pick("dkim"), dmarc=pick("dmarc"),
                       authserv_id=chosen[0], trusted=trusted)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def parse_email(
    raw: bytes,
    *,
    received_at: float,
    raw_ref: str | None = None,
    trusted_authserv_ids: tuple[str, ...] = (),
) -> EmailEvent:
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    warnings: list[str] = []
    event = EmailEvent(
        message_id=f"<sha256-{raw_sha256[:32]}@phishguard.invalid>",
        received_at=received_at, raw_ref=raw_ref, raw_sha256=raw_sha256, raw_size=len(raw),
        parse_warnings=warnings,
    )
    try:
        _fill(event, BytesParser(policy=policy.default).parsebytes(raw), trusted_authserv_ids, warnings)
    except Exception as exc:  # last line of defence: keep the evidence, flag the failure
        warnings.append(f"parse_failed:{type(exc).__name__}:{exc}"[:300])
    return event


def _fill(event: EmailEvent, msg: EmailMessage, trusted_ids: tuple[str, ...], warnings: list[str]) -> None:
    for defect in getattr(msg, "defects", [])[:10]:
        warnings.append(f"defect:{type(defect).__name__}")

    # Identity. A deterministic fallback ID (hash of the bytes) means a retried
    # delivery of the same message still dedupes downstream.
    message_id = str(msg.get("message-id", "") or "").strip()
    if message_id:
        event.message_id = message_id
    else:
        warnings.append("missing_message_id")

    senders = _addresses(msg, "from", warnings)
    if senders:
        event.from_display, event.from_addr = senders[0]
        event.from_domain = event.from_addr.rsplit("@", 1)[1]
        if len(senders) > 1:
            warnings.append("multiple_from_addresses")
    else:
        warnings.append("missing_or_invalid_from")
    reply_to = _addresses(msg, "reply-to", warnings)
    event.reply_to_addr = reply_to[0][1] if reply_to else ""
    event.to = [a for _, a in _addresses(msg, "to", warnings)]
    event.cc = [a for _, a in _addresses(msg, "cc", warnings)]
    event.subject = str(msg.get("subject", "") or "")
    event.date = str(msg.get("date", "") or "")

    event.auth = parse_auth_results([str(v) for v in msg.get_all("authentication-results", []) or []], trusted_ids)
    if event.auth.authserv_id and not event.auth.trusted:
        warnings.append("auth_results_untrusted")

    # Bodies
    plain_part = msg.get_body(preferencelist=("plain",))
    html_part = msg.get_body(preferencelist=("html",))
    plain = _safe_text(plain_part, warnings) if plain_part is not None else ""
    html_text, anchors = ("", [])
    if html_part is not None:
        event.had_html = True
        html_text, anchors = html_to_text(_safe_text(html_part, warnings))
    body = plain.strip() or html_text
    if plain.strip() and html_text and _diverges(plain, html_text):
        # The recipient's client renders the HTML; a benign plain part must not hide it from the model.
        warnings.append("plain_html_divergent")
        body = f"{plain.strip()}\n\n{html_text}"
    if len(body) > MAX_TEXT_CHARS:
        warnings.append("body_truncated")
        body = body[:MAX_TEXT_CHARS]
    event.text_body = body

    # Links: anchors from HTML keep their visible text; bare URLs from text do not have any.
    anchor_hrefs = {h for h, _ in anchors}
    anchor_texts = {t for _, t in anchors if t}
    seen: set[tuple[str, str]] = set()
    candidates = list(anchors) + [(u, "") for u in _URL_RE.findall(plain + "\n" + html_text)]
    for href, text in candidates:
        if not href.lower().startswith(("http://", "https://")) or (href, text) in seen:
            continue
        # A bare URL that is already an anchor's href adds nothing. One that is only an anchor's
        # *visible text* is not a link at all: recording it would put the decoy domain in `href`.
        if not text and (href in anchor_hrefs or href in anchor_texts):
            continue
        seen.add((href, text))
        event.links.append(Link(href=href, href_domain=host_of(href), display_text=text[:200],
                                text_domain=domain_in_text(text) if text else None))
        if len(event.links) >= MAX_LINKS:
            warnings.append("links_truncated")
            break

    # Attachments: everything that is not one of the body parts and not a container.
    body_parts = {id(p) for p in (plain_part, html_part) if p is not None}
    for part in msg.walk():
        if part.is_multipart() or id(part) in body_parts:
            continue
        if part is msg and part.get_content_maintype() == "text" and not part.is_attachment():
            continue  # single-part text message: its only part is the body
        # (A single-part message that is NOT text, e.g. a bare application/octet-stream "a.exe",
        #  falls through and is recorded as an attachment.)
        payload = part.get_payload(decode=True) or b""
        event.attachments.append(Attachment(
            filename=part.get_filename(),
            content_type=part.get_content_type(),
            size=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
        ))
