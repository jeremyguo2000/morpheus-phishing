"""End-to-end over the real Kafka protocol, using librdkafka's in-process mock
cluster (`test.mock.num.brokers`). No Docker, no JVM.

What this covers: the real client code paths for produce + delivery reports,
consumer groups, seek, and offset commits. What it does NOT cover: replication
and in-sync replicas. The mock has no real ISR, so `acks=all` /
`min.insync.replicas` durability is a property of a real multi-broker cluster
that these tests can't demonstrate.
"""

from __future__ import annotations

import io
import time

import pytest
from conftest import FIXTURES

pytestmark = pytest.mark.kafka
ck = pytest.importorskip("confluent_kafka")

from phishguard.blobstore import LocalBlobStore  # noqa: E402
from phishguard.config import Settings  # noqa: E402
from phishguard.ingest import EX_OK, EX_TEMPFAIL, ingest  # noqa: E402
from phishguard.producer import ReliableProducer  # noqa: E402
from phishguard.schema import Action, Verdict  # noqa: E402
from phishguard.worker import Worker, build_consumer  # noqa: E402


@pytest.fixture(scope="module")
def broker():
    anchor = ck.Producer({"test.mock.num.brokers": 1, "bootstrap.servers": "ignored:1"})
    meta = anchor.list_topics(timeout=10)
    b = next(iter(meta.brokers.values()))
    yield f"{b.host}:{b.port}"  # mock cluster lives as long as `anchor` does
    anchor.flush(1)


def _drain(bootstrap: str, topic: str, expect: int, timeout: float = 30.0) -> list:
    c = ck.Consumer({"bootstrap.servers": bootstrap, "group.id": f"reader-{time.time()}",
                     "auto.offset.reset": "earliest"})
    c.subscribe([topic])
    got, deadline = [], time.time() + timeout
    while len(got) < expect and time.time() < deadline:
        got += [m for m in c.consume(10, timeout=1.0) if m.error() is None]
    c.close()
    return got


def test_ingest_to_verdict_over_kafka(broker, tmp_path, pipeline):
    settings = Settings(bootstrap_servers=broker, blob_dir=str(tmp_path), consumer_group="e2e",
                        trusted_authserv_ids=("mx.example-corp.com",))
    producer = ReliableProducer(broker)
    store = LocalBlobStore(tmp_path)
    for name in ("html_only_phish.eml", "ham_multipart_comma_names.eml"):
        raw = (FIXTURES / name).read_bytes()
        assert ingest(io.BytesIO(raw), settings=settings, store=store, producer=producer) == EX_OK

    consumer = build_consumer(settings)
    consumer.subscribe([settings.inbound_topic])
    worker = Worker(consumer, producer, pipeline, settings)
    processed, deadline = 0, time.time() + 30
    while processed < 2 and time.time() < deadline:
        processed += worker.run_once()
    assert processed == 2

    # Offsets were committed: summed over partitions (records are keyed, so they spread),
    # the group's committed position is past both records.
    parts = consumer.list_topics(settings.inbound_topic, timeout=10).topics[settings.inbound_topic].partitions
    committed = consumer.committed([ck.TopicPartition(settings.inbound_topic, p) for p in parts], timeout=10)
    assert sum(max(tp.offset, 0) for tp in committed) == 2
    consumer.close()

    verdicts = {Verdict.from_json(m.value()).message_id: Verdict.from_json(m.value())
                for m in _drain(broker, settings.verdict_topic, 2)}
    assert verdicts["<abc123@paypa1-secure.com>"].action is Action.QUARANTINE
    assert verdicts["<q3-notes-1@example-corp.com>"].action is Action.ALLOW


def test_unreachable_broker_returns_tempfail(tmp_path):
    settings = Settings(bootstrap_servers="127.0.0.1:1", blob_dir=str(tmp_path))
    producer = ReliableProducer("127.0.0.1:1", {"delivery.timeout.ms": 1500, "socket.connection.setup.timeout.ms": 1000})
    raw = (FIXTURES / "html_only_phish.eml").read_bytes()
    start = time.time()
    assert ingest(io.BytesIO(raw), settings=settings, store=LocalBlobStore(tmp_path), producer=producer) == EX_TEMPFAIL
    assert time.time() - start < 10


def test_rewind_really_redelivers_after_scorer_outage(broker, tmp_path, pipeline):
    """The fakes only record that seek() was called. This proves the records come back."""
    from phishguard.scoring import ScorerUnavailable
    topic = f"rewind-{int(time.time() * 1000)}"
    settings = Settings(bootstrap_servers=broker, blob_dir=str(tmp_path), consumer_group=f"g-{topic}",
                        inbound_topic=topic, verdict_topic=f"{topic}-out", batch_size=10)
    producer = ReliableProducer(broker)
    for name in ("html_only_phish.eml", "ham_multipart_comma_names.eml", "forged_auth_header.eml"):
        raw = (FIXTURES / name).read_bytes()
        assert ingest(io.BytesIO(raw), settings=settings, store=LocalBlobStore(tmp_path), producer=producer) == EX_OK

    real, outages = pipeline.scorer, [2]

    class Flaky:  # first two batches hit an "outage"
        name, version = "flaky", "1"
        def score_batch(self, texts):
            if outages[0] > 0:
                outages[0] -= 1
                raise ScorerUnavailable("triton restarting")
            return real.score_batch(texts)
    pipeline.scorer = Flaky()

    consumer = build_consumer(settings)
    consumer.subscribe([topic])
    worker = Worker(consumer, producer, pipeline, settings, sleep=lambda s: None)
    processed, deadline = 0, time.time() + 30
    while processed < 3 and time.time() < deadline:
        processed += worker.run_once()
    consumer.close()
    assert outages == [0] and processed == 3          # outage happened, then every record was processed
    verdicts = _drain(broker, settings.verdict_topic, 3)
    assert len({Verdict.from_json(m.value()).event_id for m in verdicts}) == 3
