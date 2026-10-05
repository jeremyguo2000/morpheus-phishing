"""In-memory stand-ins for confluent_kafka objects, so unit tests need no broker."""

from __future__ import annotations


class FakeMessage:
    def __init__(self, value: bytes, offset: int, partition: int = 0, topic: str = "email-security",
                 key: bytes | None = None, error=None):
        self._v, self._o, self._p, self._t, self._k, self._e = value, offset, partition, topic, key, error

    def value(self): return self._v
    def offset(self): return self._o
    def partition(self): return self._p
    def topic(self): return self._t
    def key(self): return self._k
    def error(self): return self._e


class FakeConsumer:
    def __init__(self, batches):
        self.batches = list(batches)
        self.commits: list = []
        self.seeks: list = []
        self.closed = False

    def subscribe(self, topics): self.topics = topics
    def consume(self, num_messages, timeout): return self.batches.pop(0) if self.batches else []
    def commit(self, offsets, asynchronous): self.commits.append([(o.topic, o.partition, o.offset) for o in offsets])
    def seek(self, tp): self.seeks.append((tp.topic, tp.partition, tp.offset))
    def close(self): self.closed = True


class FakeKafkaClient:
    """Mimics confluent_kafka.Producer: produce() queues, flush() fires delivery callbacks."""

    def __init__(self, *, fail_with=None, never_deliver=False, raise_on_produce=None):
        self.queued, self.delivered = [], []
        self.fail_with, self.never_deliver, self.raise_on_produce = fail_with, never_deliver, raise_on_produce

    def produce(self, topic, key=None, value=None, on_delivery=None):
        if self.raise_on_produce:
            raise self.raise_on_produce
        self.queued.append((topic, key, value, on_delivery))

    def poll(self, timeout=0): return 0

    def flush(self, timeout=None):
        if self.never_deliver:
            return len(self.queued)
        for topic, key, value, cb in self.queued:
            if self.fail_with is None:
                self.delivered.append((topic, key, value))
            if cb:
                cb(self.fail_with, None)
        self.queued = []
        return 0
