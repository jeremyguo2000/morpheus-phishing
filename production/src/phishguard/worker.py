"""The scoring worker: consume -> score -> produce -> commit.

This replaces the Morpheus pipeline's role in the PoC (the stage graph in
run.py) with plain Python, so every reliability decision is visible.

Delivery semantics: AT-LEAST-ONCE.
  1. Auto-commit is off. Offsets are committed only after every verdict and
     DLQ record for the batch has been acknowledged by the broker.
  2. If anything fails before the commit, we seek back to the first offset of
     the batch and try again. Nothing is skipped.
  3. The cost: a batch that partly produced and then failed is produced again,
     so the verdict topic can contain duplicates. Verdicts are keyed by
     event_id (hash of the raw message) and remediation (quarantine) is
     idempotent, so a duplicate is harmless. Kafka transactions
     (send_offsets_to_transaction + read_committed consumers) would make THIS
     consume-produce step exactly-once, but not the system: ingest retries by
     Postfix and side effects like quarantining happen outside Kafka. Worth it
     only if duplicates actually hurt.

Failure handling, by type:
  * Bad record (unparseable, unknown schema version)  -> DLQ, not retried.
  * Model serving down (ScorerUnavailable)             -> rewind + backoff, retried.
  * Bug triggered by one specific record ("poison pill")
                                                       -> batch is re-scored one record
                                                          at a time; the bad one goes to
                                                          the DLQ, the rest proceed. Without
                                                          this, one email can stall a
                                                          partition forever.
"""

from __future__ import annotations

import base64
import json
import logging
import time
from collections.abc import Callable
from typing import Any

from . import metrics
from .config import Settings
from .pipeline import Pipeline
from .producer import ReliableProducer
from .schema import EmailEvent, SchemaError, Verdict
from .scoring import ScorerUnavailable

log = logging.getLogger("phishguard.worker")

CONSUMER_CONF = {
    "enable.auto.commit": False,
    "auto.offset.reset": "earliest",
    "partition.assignment.strategy": "cooperative-sticky",  # rebalances don't stop the whole group
}


class Worker:
    def __init__(self, consumer: Any, producer: ReliableProducer, pipeline: Pipeline, settings: Settings, *,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.time,
                 flush_timeout: float = 25.0):
        # flush_timeout > producer delivery.timeout.ms (20s): we wait for a definite report
        # instead of giving up while librdkafka is still retrying (which guarantees duplicates).
        self.consumer, self.producer, self.pipeline, self.settings = consumer, producer, pipeline, settings
        self._sleep, self._clock, self._flush_timeout = sleep, clock, flush_timeout
        self._backoff = 0.0
        metrics.MODEL.info({"name": pipeline.scorer.name, "version": pipeline.scorer.version})

    def run(self, should_stop: Callable[[], bool]) -> None:
        self.consumer.subscribe([self.settings.inbound_topic])
        try:
            while not should_stop():
                self.run_once()
        finally:
            self.consumer.close()  # leaves the group cleanly so partitions reassign quickly

    def run_once(self) -> int:
        """Process one batch. Returns the number of records whose offsets were committed."""
        messages = self.consumer.consume(num_messages=self.settings.batch_size, timeout=1.0)
        records = []
        for m in messages or []:
            if m.error() is not None:
                log.warning("consumer error: %s", m.error())
                continue
            records.append(m)
        if not records:
            return 0

        started = self._clock()
        events: list[tuple[Any, EmailEvent]] = []
        dead: list[tuple[Any, str, str]] = []
        for m in records:
            try:
                events.append((m, EmailEvent.from_json(m.value())))
            except SchemaError as exc:
                dead.append((m, "schema", str(exc)))

        try:
            scored, poison = self._score(events)
        except ScorerUnavailable as exc:
            return self._retry_later(records, "scorer_unavailable", exc)
        dead += poison

        if not self._produce(scored, dead):
            return self._retry_later(records, "produce_failed", None)

        self._commit(records)
        self._backoff = 0.0
        now = self._clock()
        for event, verdict in scored:
            metrics.VERDICTS.labels(verdict.action.value).inc()
            metrics.SCORE.observe(verdict.score)
            metrics.END_TO_END.observe(max(0.0, now - event.received_at))
        for _, reason, _ in dead:
            metrics.DLQ.labels(reason).inc()
        metrics.BATCH_SECONDS.observe(now - started)
        return len(records)

    # -- steps ---------------------------------------------------------------

    def _score(self, events):
        """Score the whole batch; if an unexpected error occurs, isolate the record causing it."""
        if not events:
            return [], []
        try:
            verdicts = self.pipeline.score([e for _, e in events])
            return list(zip((e for _, e in events), verdicts)), []
        except ScorerUnavailable:
            raise
        except Exception:
            log.exception("batch scoring failed; isolating records")
        scored, poison = [], []
        for m, event in events:
            try:
                scored.append((event, self.pipeline.score([event])[0]))
            except ScorerUnavailable:
                raise
            except Exception as exc:
                poison.append((m, "processing_error", f"{type(exc).__name__}: {exc}"[:500]))
        return scored, poison

    def _produce(self, scored: list[tuple[EmailEvent, Verdict]], dead) -> bool:
        failures: list[Any] = []

        def on_delivery(err, _msg):
            if err is not None:
                failures.append(err)

        try:
            for _, verdict in scored:
                self.producer.produce_async(self.settings.verdict_topic, verdict.event_id,
                                            verdict.to_json(), on_delivery)
            for m, reason, detail in dead:
                key = (m.key() or b"").decode("utf-8", "replace") or f"{m.topic()}-{m.partition()}-{m.offset()}"
                self.producer.produce_async(self.settings.dlq_topic, key, _dlq_record(m, reason, detail),
                                            on_delivery)
        except Exception as exc:  # local queue full, message too large, ...
            log.error("produce failed locally: %s", exc)
            return False
        remaining = self.producer.flush(self._flush_timeout)
        if remaining or failures:
            log.error("produce not confirmed: %d pending, %d failed (%s)", remaining, len(failures),
                      failures[:1])
            return False
        return True

    def _commit(self, records) -> None:
        from confluent_kafka import TopicPartition
        highest: dict[tuple[str, int], int] = {}
        for m in records:
            tp = (m.topic(), m.partition())
            highest[tp] = max(highest.get(tp, -1), m.offset())
        # Committed offset = the NEXT offset to read, hence +1.
        offsets = [TopicPartition(t, p, o + 1) for (t, p), o in highest.items()]
        try:
            results = self.consumer.commit(offsets=offsets, asynchronous=False)
        except Exception as exc:
            # Usually a rebalance took the partition away. The new owner will re-read from the
            # last committed offset: duplicates, not loss. That is the at-least-once trade.
            log.warning("commit failed (records will be reprocessed): %s", exc)
            return
        # A synchronous commit can also fail per partition without raising.
        for tp in results or []:
            if getattr(tp, "error", None):
                log.warning("commit failed for %s[%d] (records will be reprocessed): %s",
                            tp.topic, tp.partition, tp.error)

    def _retry_later(self, records, cause: str, exc: Exception | None) -> int:
        from confluent_kafka import TopicPartition
        lowest: dict[tuple[str, int], int] = {}
        for m in records:
            tp = (m.topic(), m.partition())
            lowest[tp] = min(lowest.get(tp, m.offset()), m.offset())
        for (t, p), o in lowest.items():
            self.consumer.seek(TopicPartition(t, p, o))
        self._backoff = min(30.0, max(0.5, self._backoff * 2))
        metrics.BATCH_RETRIES.labels(cause).inc()
        log.warning("%s (%s); rewound %d partition(s), retrying in %.1fs", cause, exc, len(lowest), self._backoff)
        self._sleep(self._backoff)
        return 0


def _dlq_record(m, reason: str, detail: str) -> bytes:
    value = m.value() or b""
    return json.dumps({
        "reason": reason,
        "detail": detail,
        "source": {"topic": m.topic(), "partition": m.partition(), "offset": m.offset()},
        "value_b64": base64.b64encode(value).decode("ascii"),
        "failed_at": time.time(),
    }).encode("utf-8")


def build_consumer(settings: Settings):
    from confluent_kafka import Consumer
    return Consumer({**CONSUMER_CONF, "bootstrap.servers": settings.bootstrap_servers,
                     "group.id": settings.consumer_group})
