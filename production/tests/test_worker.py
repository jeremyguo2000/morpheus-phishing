from __future__ import annotations

import base64
import json

import pytest
from conftest import load
from fakes import FakeConsumer, FakeKafkaClient, FakeMessage

from phishguard.config import Settings
from phishguard.producer import ReliableProducer
from phishguard.schema import Action, Verdict
from phishguard.scoring import ScorerUnavailable
from phishguard.worker import Worker

SETTINGS = Settings(batch_size=10)


def msg(name: str, offset: int, partition: int = 0) -> FakeMessage:
    return FakeMessage(load(name).to_json(), offset, partition)


def make_worker(batches, pipeline, client=None):
    consumer = FakeConsumer(batches)
    client = client or FakeKafkaClient()
    sleeps: list[float] = []
    worker = Worker(consumer, ReliableProducer("x", client=client), pipeline, SETTINGS, sleep=sleeps.append)
    return worker, consumer, client, sleeps


def test_happy_path_produces_verdicts_then_commits_next_offsets(pipeline):
    batch = [msg("html_only_phish.eml", 10), msg("ham_multipart_comma_names.eml", 11),
             msg("attachment_double_ext.eml", 5, partition=1)]
    worker, consumer, client, _ = make_worker([batch], pipeline)
    assert worker.run_once() == 3
    verdicts = [Verdict.from_json(v) for t, _, v in client.delivered if t == SETTINGS.verdict_topic]
    assert all(k == v.event_id.encode() for (t, k, _), v in
               zip([d for d in client.delivered if d[0] == SETTINGS.verdict_topic], verdicts))
    assert {v.action for v in verdicts} >= {Action.QUARANTINE, Action.ALLOW}
    assert sorted(consumer.commits[0]) == [("email-security", 0, 12), ("email-security", 1, 6)]


def test_bad_record_goes_to_dlq_and_batch_still_commits(pipeline):
    batch = [FakeMessage(b"{not json", 0, key=b"k1"), FakeMessage(b'{"schema_version": 99}', 1),
             FakeMessage(None, 2),                                   # null value / tombstone
             FakeMessage(b'{"schema_version": 1, "auth": "x"}', 3),  # wrong nesting
             msg("ham_multipart_comma_names.eml", 4)]
    worker, consumer, client, _ = make_worker([batch], pipeline)
    assert worker.run_once() == 5
    dlq = [json.loads(v) for t, _, v in client.delivered if t == SETTINGS.dlq_topic]
    assert [d["reason"] for d in dlq] == ["schema"] * 4
    assert base64.b64decode(dlq[0]["value_b64"]) == b"{not json"  # original preserved for replay
    assert consumer.commits == [[("email-security", 0, 5)]]


def test_scorer_down_rewinds_and_does_not_commit(pipeline):
    class DownScorer:
        name, version = "down", "0"
        def score_batch(self, texts): raise ScorerUnavailable("triton unreachable")
    pipeline.scorer = DownScorer()
    batch = [msg("html_only_phish.eml", 7), msg("ham_multipart_comma_names.eml", 8)]
    worker, consumer, client, sleeps = make_worker([batch, batch], pipeline)
    assert worker.run_once() == 0
    assert consumer.commits == [] and client.delivered == []
    assert consumer.seeks == [("email-security", 0, 7)]   # back to the FIRST offset of the batch
    worker.run_once()
    assert sleeps == [0.5, 1.0]                             # exponential backoff


def test_unconfirmed_produce_rewinds_and_does_not_commit(pipeline):
    worker, consumer, _, _ = make_worker([[msg("html_only_phish.eml", 3)]], pipeline,
                                         client=FakeKafkaClient(fail_with="BROKER_DOWN"))
    assert worker.run_once() == 0
    assert consumer.commits == [] and consumer.seeks == [("email-security", 0, 3)]


def test_poison_pill_is_isolated_and_the_rest_proceed(pipeline):
    real = pipeline.scorer

    class Fragile:
        name, version = "fragile", "1"
        def score_batch(self, texts):
            if any("favour" in t for t in texts):
                raise ValueError("tokenizer blew up")
            return real.score_batch(texts)
    pipeline.scorer = Fragile()
    batch = [msg("html_only_phish.eml", 0), msg("forged_auth_header.eml", 1), msg("ham_multipart_comma_names.eml", 2)]
    worker, consumer, client, _ = make_worker([batch], pipeline)
    assert worker.run_once() == 3
    topics = [t for t, _, _ in client.delivered]
    assert topics.count(SETTINGS.verdict_topic) == 2 and topics.count(SETTINGS.dlq_topic) == 1
    assert consumer.commits == [[("email-security", 0, 3)]]


def test_run_closes_consumer(pipeline):
    worker, consumer, _, _ = make_worker([], pipeline)
    calls = iter([False, True])
    worker.run(lambda: next(calls))
    assert consumer.closed


@pytest.mark.parametrize("batch", [[], [FakeMessage(b"", 0, error="PARTITION_EOF")]])
def test_empty_or_error_only_batches_commit_nothing(pipeline, batch):
    worker, consumer, _, _ = make_worker([batch], pipeline)
    assert worker.run_once() == 0 and consumer.commits == []
