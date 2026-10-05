"""The contract between pipeline stages.

In the PoC, the JSON on the topic was "whatever dict the producer built". Every
consumer then had to guess field names and types (e.g. was `is_phishing` a float
or a bool?). Here the shape is explicit and versioned:

* `schema_version` lets old and new producers/consumers coexist during a rollout.
  A consumer that sees a version it does not understand sends the record to the
  dead-letter topic instead of guessing.
* In production you would register these as Avro/Protobuf schemas in a schema
  registry so compatibility is checked at publish time. Dataclasses keep this
  reference dependency-free while showing the same idea.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

SCHEMA_VERSION = 1


class SchemaError(ValueError):
    """Record cannot be decoded into the expected schema. Not retryable."""


@dataclass
class AuthResults:
    spf: str | None = None    # pass | fail | softfail | neutral | none | temperror | permerror
    dkim: str | None = None
    dmarc: str | None = None
    authserv_id: str | None = None
    trusted: bool = False      # True only if stamped by an authserv-id we control


@dataclass
class Link:
    href: str
    href_domain: str | None
    display_text: str = ""
    text_domain: str | None = None  # set when the visible text itself looks like a URL/domain


@dataclass
class Attachment:
    filename: str | None
    content_type: str
    size: int
    sha256: str


@dataclass
class EmailEvent:
    message_id: str
    received_at: float                 # unix seconds, set at ingest; used for end-to-end latency
    raw_ref: str | None                # claim-check pointer to the original bytes
    raw_sha256: str
    raw_size: int
    from_addr: str = ""
    from_display: str = ""
    from_domain: str = ""
    reply_to_addr: str = ""
    to: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    subject: str = ""
    date: str = ""
    text_body: str = ""
    had_html: bool = False
    links: list[Link] = field(default_factory=list)
    auth: AuthResults = field(default_factory=AuthResults)
    attachments: list[Attachment] = field(default_factory=list)
    parse_warnings: list[str] = field(default_factory=list)
    labels: dict[str, Any] = field(default_factory=dict)  # e.g. synthetic ground truth; never used for scoring
    schema_version: int = SCHEMA_VERSION

    @property
    def event_id(self) -> str:
        """Identity for dedupe and Kafka keys. NOT the Message-ID: that header is chosen
        by the sender, is not guaranteed unique, and a phish can reuse a legitimate
        message's ID. The hash of the exact bytes is stable across retries of the same
        delivery and cannot be forged to collide."""
        return self.raw_sha256

    def to_json(self) -> bytes:
        # ensure_ascii=False: non-Latin text stays UTF-8 instead of 6-byte \uXXXX escapes,
        # which matters for staying under Kafka's message size limit.
        return json.dumps(asdict(self), separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    @classmethod
    def from_json(cls, data: bytes | str | None) -> "EmailEvent":
        if not isinstance(data, (bytes, str)):
            # e.g. a tombstone / null-value record. Must be a SchemaError so it goes to the
            # DLQ; a TypeError here would crash the worker on the same record forever.
            raise SchemaError(f"record value is {type(data).__name__}, expected JSON bytes")
        try:
            d = json.loads(data)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise SchemaError(f"not valid JSON: {exc}") from exc
        if not isinstance(d, dict):
            raise SchemaError("top-level JSON is not an object")
        version = d.get("schema_version")
        if version != SCHEMA_VERSION:
            raise SchemaError(f"unsupported schema_version {version!r} (expected {SCHEMA_VERSION})")
        try:
            d["auth"] = AuthResults(**d.get("auth", {}))
            d["links"] = [Link(**x) for x in d.get("links", [])]
            d["attachments"] = [Attachment(**x) for x in d.get("attachments", [])]
            return cls(**d)
        except (TypeError, AttributeError) as exc:  # missing/unknown fields, wrong nesting
            raise SchemaError(f"field mismatch: {exc}") from exc


class Action(str, Enum):
    ALLOW = "allow"
    TAG = "tag"                # deliver, but add a warning banner / header
    QUARANTINE = "quarantine"  # pull from mailbox, hold for analyst review


@dataclass
class Reason:
    signal: str
    weight: float
    detail: str


@dataclass
class Verdict:
    message_id: str              # for humans and for finding the message in mailboxes
    event_id: str                # for dedupe/joins (see EmailEvent.event_id)
    score: float                # combined score in [0, 1]; NOT a calibrated probability until you calibrate it
    action: Action
    reasons: list[Reason]
    model_name: str
    model_version: str
    model_score: float | None    # raw text-model output, kept separately for evaluation/drift monitoring
    scored_at: float
    schema_version: int = SCHEMA_VERSION

    def to_json(self) -> bytes:
        d = asdict(self)
        d["action"] = self.action.value
        return json.dumps(d, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    @classmethod
    def from_json(cls, data: bytes | str) -> "Verdict":
        d = json.loads(data)
        d["action"] = Action(d["action"])
        d["reasons"] = [Reason(**r) for r in d.get("reasons", [])]
        return cls(**d)
