"""Postfix pipe entry point: raw message on stdin -> claim-check store -> Kafka.

How this is wired into Postfix matters more than the code (see docs/DESIGN.md):
in the PoC the pipe was the *delivery* transport, so mail went to Kafka and
never reached a mailbox. Here the intended wiring is a COPY: a BCC map sends a
duplicate of each inbound message to a pipe transport, so normal delivery is
unaffected and this pipeline does post-delivery detection and remediation.

Exit codes follow sysexits.h, because that is how pipe(8) decides what to do:
    0   EX_OK        accepted; Postfix removes it from the queue
    75  EX_TEMPFAIL  storage/Kafka unavailable, or we crashed; Postfix keeps it queued and retries
    65  EX_DATAERR   input that can never succeed (empty, over the size limit); not retried
Any OTHER non-zero status (e.g. 1 from an uncaught exception) is a hard bounce,
so main() turns every unexpected error into 75. The PoC printed "200"/"400"
to stdout, which isn't a protocol Postfix uses. Note that since Postfix 2.3,
output that starts with an enhanced status code such as "5.x.x" can override
the exit status, so this command keeps stdout clean.

A copy made by a BCC map is sent without delivery notifications. A bounced
copy therefore notifies nobody and only appears in the mail log. Permanent
failures are logged at ERROR for that reason, and should be alerted on.

Process-per-message is the cost of the pipe interface (interpreter start +
broker connection per email). That's acceptable for a copy feed of moderate
volume; at high volume, replace this with a long-running SMTP content-filter
or milter process that keeps one producer open.
"""

from __future__ import annotations

import logging
import sys
import time
from typing import BinaryIO

from .blobstore import BlobStore, LocalBlobStore
from .config import Settings
from .parsing import parse_email
from .producer import DeliveryError, RecordTooLarge, ReliableProducer
from .schema import EmailEvent

EX_OK, EX_DATAERR, EX_TEMPFAIL = 0, 65, 75

# Stay well under Kafka's default ~1 MB message.max.bytes. The raw message is in
# blob storage, so the event only needs enough text for scoring.
MAX_EVENT_BYTES = 900_000

log = logging.getLogger("phishguard.ingest")


def fit_event(event: EmailEvent, max_bytes: int = MAX_EVENT_BYTES) -> bytes:
    """Serialize, shrinking the body and lists until the event fits. The full message
    is still in blob storage, so this loses nothing permanently."""
    data = event.to_json()
    while len(data) > max_bytes:
        if len(event.text_body) > 1_000:
            event.text_body = event.text_body[: len(event.text_body) // 2]
        elif len(event.links) > 20 or len(event.attachments) > 20 or len(event.to) + len(event.cc) > 50:
            event.links, event.attachments = event.links[:20], event.attachments[:20]
            event.to, event.cc = event.to[:50], event.cc[:50]
        else:
            break  # can't shrink further; producer will raise RecordTooLarge
        if "event_shrunk" not in event.parse_warnings:
            event.parse_warnings.append("event_shrunk")
        data = event.to_json()
    return data


def ingest(stream: BinaryIO, *, settings: Settings, store: BlobStore, producer: ReliableProducer,
           now: float | None = None) -> int:
    raw = stream.read(settings.max_message_bytes + 1)
    if not raw:
        log.error("empty message on stdin")
        return EX_DATAERR
    if len(raw) > settings.max_message_bytes:
        log.error("message exceeds %d bytes; NOT analysed", settings.max_message_bytes)
        return EX_DATAERR

    try:
        ref = store.put(raw)
    except OSError as exc:
        log.error("blob store unavailable: %s", exc)
        return EX_TEMPFAIL

    event = parse_email(raw, received_at=now if now is not None else time.time(), raw_ref=ref,
                        trusted_authserv_ids=settings.trusted_authserv_ids)
    try:
        # Key = hash of the raw bytes: all retries of this message land on the same partition and
        # are trivially identifiable as duplicates. (Not Message-ID: the sender controls that.)
        producer.send_and_wait(settings.inbound_topic, event.event_id, fit_event(event))
    except RecordTooLarge as exc:
        log.error("event for %s too large even after shrinking; NOT analysed: %s", event.message_id, exc)
        return EX_DATAERR
    except DeliveryError as exc:
        log.error("kafka delivery failed for %s: %s", event.message_id, exc)
        return EX_TEMPFAIL

    log.info("ingested %s (%d bytes, %d warnings)", event.message_id, event.raw_size, len(event.parse_warnings))
    return EX_OK


def main() -> int:
    """Never exits with anything but 0/65/75. A crash, a bad deploy or a config typo becomes
    75, so Postfix keeps the copy and retries after the fix, instead of bouncing it silently."""
    try:
        settings = Settings()
        store = LocalBlobStore(settings.blob_dir)
        producer = ReliableProducer(settings.bootstrap_servers)
        return ingest(sys.stdin.buffer, settings=settings, store=store, producer=producer)
    except BaseException as exc:  # includes KeyboardInterrupt/SystemExit from deep inside libraries
        try:
            log.exception("ingest crashed: %s", exc)
        finally:
            return EX_TEMPFAIL  # noqa: B012 - deliberately swallow: the exit code IS the error report
