from __future__ import annotations

import io

import pytest
from conftest import FIXTURES
from fakes import FakeKafkaClient

from phishguard.blobstore import LocalBlobStore
from phishguard.config import Settings
from phishguard.ingest import EX_DATAERR, EX_OK, EX_TEMPFAIL, MAX_EVENT_BYTES, fit_event, ingest
from phishguard.producer import DeliveryError, RecordTooLarge, ReliableProducer
from phishguard.schema import EmailEvent

RAW = (FIXTURES / "html_only_phish.eml").read_bytes()


# -- producer ---------------------------------------------------------------

def test_send_and_wait_succeeds_only_on_clean_delivery_report():
    client = FakeKafkaClient()
    ReliableProducer("x", client=client).send_and_wait("t", "k", b"v")
    assert client.delivered == [("t", b"k", b"v")]


@pytest.mark.parametrize("client", [
    FakeKafkaClient(fail_with="KafkaError{MSG_TIMED_OUT}"),  # broker never acked
    FakeKafkaClient(never_deliver=True),                       # flush timed out with records pending
    FakeKafkaClient(raise_on_produce=BufferError("queue full")),
], ids=["delivery-error", "flush-timeout", "local-queue-full"])
def test_send_and_wait_raises_instead_of_pretending(client):
    # The PoC never checked the send result, so failures like these were invisible
    # (in kafka-python, flush() returns normally even if a send ultimately failed).
    with pytest.raises(DeliveryError):
        ReliableProducer("x", client=client).send_and_wait("t", "k", b"v", timeout=0.01)


# -- ingest -----------------------------------------------------------------

@pytest.fixture
def settings(tmp_path):
    return Settings(blob_dir=str(tmp_path), max_message_bytes=100_000, trusted_authserv_ids=("mx.example-corp.com",))


def test_ingest_stores_raw_and_publishes_keyed_event(settings, tmp_path):
    client = FakeKafkaClient()
    store = LocalBlobStore(tmp_path)
    code = ingest(io.BytesIO(RAW), settings=settings, store=store, producer=ReliableProducer("x", client=client),
                  now=123.0)
    assert code == EX_OK
    topic, key, value = client.delivered[0]
    event = EmailEvent.from_json(value)
    assert topic == settings.inbound_topic
    assert event.message_id == "<abc123@paypa1-secure.com>"
    assert key == event.event_id.encode() == event.raw_sha256.encode()  # key on bytes, not sender-chosen ID
    assert store.get(event.raw_ref) == RAW and event.received_at == 123.0


def test_ingest_is_idempotent_on_storage(settings, tmp_path):
    store = LocalBlobStore(tmp_path)
    assert store.put(RAW) == store.put(RAW)


def test_kafka_down_means_tempfail_so_postfix_retries(settings, tmp_path):
    producer = ReliableProducer("x", client=FakeKafkaClient(never_deliver=True))
    assert ingest(io.BytesIO(RAW), settings=settings, store=LocalBlobStore(tmp_path), producer=producer) == EX_TEMPFAIL


def test_storage_down_means_tempfail(settings):
    class BrokenStore:
        def put(self, data): raise OSError("disk full")
    producer = ReliableProducer("x", client=FakeKafkaClient())
    assert ingest(io.BytesIO(RAW), settings=settings, store=BrokenStore(), producer=producer) == EX_TEMPFAIL


@pytest.mark.parametrize("raw", [b"", b"x" * 100_001], ids=["empty", "oversized"])
def test_unusable_input_is_a_permanent_failure(settings, tmp_path, raw):
    producer = ReliableProducer("x", client=FakeKafkaClient())
    assert ingest(io.BytesIO(raw), settings=settings, store=LocalBlobStore(tmp_path), producer=producer) == EX_DATAERR


def test_blob_store_rejects_paths_outside_root(tmp_path):
    with pytest.raises(ValueError):
        LocalBlobStore(tmp_path).get("file:///etc/passwd")


def test_oversized_record_is_permanent_not_retried(settings, tmp_path):
    # Retrying a too-large record can never succeed; as a TEMPFAIL Postfix would retry for days, then drop it.
    from confluent_kafka import KafkaError, KafkaException
    producer = ReliableProducer("x", client=FakeKafkaClient(
        raise_on_produce=KafkaException(KafkaError(KafkaError.MSG_SIZE_TOO_LARGE))))
    with pytest.raises(RecordTooLarge):
        producer.send_and_wait("t", "k", b"v")
    assert ingest(io.BytesIO(RAW), settings=settings, store=LocalBlobStore(tmp_path), producer=producer) == EX_DATAERR


def _cjk_email(chars: int) -> bytes:
    body = ("\u4f60\u597d\u4e16\u754c " * (chars // 5)).encode("utf-8")
    return b"From: a@b.example\r\nSubject: big\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + body


def test_large_non_ascii_email_produces_an_event_under_the_kafka_limit(tmp_path):
    # ~2 MB of CJK text. With json's default ensure_ascii, each character became a 6-byte
    # \\uXXXX escape and the event blew past Kafka's ~1 MB limit.
    big_settings = Settings(blob_dir=str(tmp_path), max_message_bytes=5_000_000)
    client = FakeKafkaClient()
    assert ingest(io.BytesIO(_cjk_email(750_000)), settings=big_settings, store=LocalBlobStore(tmp_path),
                  producer=ReliableProducer("x", client=client)) == EX_OK
    assert len(client.delivered[0][2]) <= MAX_EVENT_BYTES


def test_fit_event_shrinks_until_it_fits():
    from phishguard.parsing import parse_email
    event = parse_email(_cjk_email(100_000), received_at=0)
    data = fit_event(event, max_bytes=50_000)
    assert len(data) <= 50_000
    shrunk = EmailEvent.from_json(data)
    assert "event_shrunk" in shrunk.parse_warnings and shrunk.text_body.startswith("\u4f60")


def test_ingest_main_turns_any_crash_into_tempfail(monkeypatch):
    import phishguard.ingest as ingest_mod

    def boom():
        raise RuntimeError("bad deploy")
    monkeypatch.setattr(ingest_mod, "Settings", boom)
    assert ingest_mod.main() == EX_TEMPFAIL  # never 1: Postfix would hard-bounce the copy
