"""A Kafka producer that only reports success after the broker has the record.

The PoC bug this fixes: with kafka-python, `producer.send()` returns a future and
`producer.flush()` waits for in-flight sends but does NOT raise if a send
ultimately failed. The PoC never checked the future, so it could print "200",
exit 0, and Postfix would consider the mail handled while the record was lost.

Here, success means a delivery report with no error arrived within the timeout.

Settings and why:
  acks=all             leader waits for all in-sync replicas before acking.
                       With min.insync.replicas=2 on the topic, one broker dying
                       cannot lose an acked record.
  enable.idempotence   broker dedupes producer retries (no duplicates from
                       *internal* retries within one producer session).
  delivery.timeout.ms  upper bound on how long librdkafka keeps retrying.

What idempotence does NOT give you: if this process times out and Postfix
retries the whole delivery, a new producer sends the record again. So the
system is at-least-once end to end, and consumers must tolerate duplicates
(records are keyed by a hash of the raw message, so they are easy to spot).

Not every failure is worth retrying. A record larger than the broker allows
(MSG_SIZE_TOO_LARGE) fails the same way every time, so it raises
RecordTooLarge, which the caller must treat as permanent. Treating it as
temporary means retrying for days and then dropping it silently.
"""

from __future__ import annotations

from typing import Any

DEFAULT_CONF: dict[str, Any] = {
    "acks": "all",
    "enable.idempotence": True,
    "delivery.timeout.ms": 20_000,
    "linger.ms": 5,
    "compression.type": "zstd",
}


class DeliveryError(RuntimeError):
    """The record was not confirmed by the broker. Retryable by the caller."""


class RecordTooLarge(DeliveryError):
    """The record exceeds the size limit. Permanent: retrying cannot succeed."""


def _is_size_error(err: Any) -> bool:
    """True for librdkafka's MSG_SIZE_TOO_LARGE, whether raised by produce() or in a delivery report."""
    if err is None:
        return False
    kafka_error = err.args[0] if isinstance(err, Exception) and err.args else err
    code = getattr(kafka_error, "code", None)
    if callable(code):
        from confluent_kafka import KafkaError
        return code() == KafkaError.MSG_SIZE_TOO_LARGE
    return "MSG_SIZE_TOO_LARGE" in str(err)


class ReliableProducer:
    def __init__(self, bootstrap_servers: str, extra_conf: dict[str, Any] | None = None, *, client: Any = None):
        if client is None:
            from confluent_kafka import Producer  # imported lazily so tests can inject a fake
            conf = {**DEFAULT_CONF, "bootstrap.servers": bootstrap_servers, **(extra_conf or {})}
            client = Producer(conf)
        self._client = client

    def send_and_wait(self, topic: str, key: str, value: bytes, timeout: float = 25.0) -> None:
        """Produce one record and block until the broker confirms it. Raises DeliveryError otherwise."""
        outcome: dict[str, Any] = {}

        def on_delivery(err, msg):
            outcome["err"] = err
            outcome["done"] = True

        try:
            self._client.produce(topic, key=key.encode("utf-8"), value=value, on_delivery=on_delivery)
        except Exception as exc:  # BufferError (queue full), KafkaException (e.g. message too large)
            if _is_size_error(exc):
                raise RecordTooLarge(f"record of {len(value)} bytes rejected: {exc}") from exc
            raise DeliveryError(f"produce rejected locally: {exc}") from exc

        remaining = self._client.flush(timeout)
        if remaining > 0 or not outcome.get("done"):
            # The record may still be delivered later; we just can't confirm it. Caller must treat
            # this as failure (so it gets retried) and downstream must tolerate the possible duplicate.
            raise DeliveryError(f"no delivery report within {timeout}s")
        if outcome["err"] is not None:
            if _is_size_error(outcome["err"]):
                raise RecordTooLarge(f"broker rejected {len(value)}-byte record: {outcome['err']}")
            raise DeliveryError(f"broker rejected record: {outcome['err']}")

    def produce_async(self, topic: str, key: str, value: bytes, on_delivery) -> None:
        """For batch use in the worker: queue a record; caller flushes and inspects reports."""
        self._client.produce(topic, key=key.encode("utf-8"), value=value, on_delivery=on_delivery)

    def poll(self, timeout: float = 0) -> int:
        return self._client.poll(timeout)

    def flush(self, timeout: float) -> int:
        return self._client.flush(timeout)
