# phishguard: production reference for the Morpheus phishing PoC

> **About this directory.** The original PoC (repository root) is my work from
> PTC. This `production/` directory is a **reference implementation written
> with Claude as a study aid**: it shows what the PoC would need to become a
> production system. It lives on its own branch so the line between the two
> stays clear in git history.

Read [`docs/DESIGN.md`](docs/DESIGN.md) first. It explains the decisions; the
code shows how they're implemented.

## Quickstart (no GPU, no Docker, no Kafka needed)

```bash
cd production
pip install -e '.[dev]'
```

```bash
python -m pytest -q
```

Score an email and see *why* it got its verdict:

```bash
export PHISHGUARD_TRUSTED_AUTHSERV_IDS=mx.example-corp.com
```

```bash
phishguard score tests/fixtures/html_only_phish.eml
```

Generate a labelled synthetic corpus and evaluate:

```bash
phishguard synth /tmp/corpus --n 300
```

```bash
phishguard evaluate --eml-dir /tmp/corpus
```

```bash
phishguard evaluate --eml-dir /tmp/corpus --model-only
```

With a real Kafka (see `deploy/docker-compose.yaml`), run `phishguard worker`
and pipe messages in with `phishguard ingest < message.eml`.

## How to read the code

In this order. Each module's docstring says what changed from the PoC and why.

| # | File | What to look for |
|---|---|---|
| 1 | `schema.py` | Versioned contract between stages; why a consumer rejects unknown versions |
| 2 | `parsing.py` | Bytes not str, HTML links with visible text, trusted `Authentication-Results`, never raises |
| 3 | `producer.py` | The PoC's silent-loss bug and how a delivery report fixes it |
| 4 | `ingest.py` | Postfix exit codes (`75` = retry later), claim-check storage, copy vs delivery |
| 5 | `scoring/rules.py` | Signals the body-text model can't see |
| 6 | `scoring/combine.py` | Noisy-OR: explainable, and its known weakness |
| 7 | `decision.py` | Different thresholds per action; why allowlists are dangerous |
| 8 | `worker.py` | At-least-once: commit after produce, rewind on failure, DLQ, poison pills |
| 9 | `evaluate.py` | Precision/recall across thresholds |
| 10 | `tests/` | `test_worker.py` and `test_kafka_e2e.py` show the failure behaviour concretely |

## Interview questions, with answers

Each answer is phrased the way you'd say it out loud: what the PoC did, then
what production needs. *Code:* lines tell you where to look if you want to
go deeper; you don't need them to answer.

### "Does the user still get their email?"
In the PoC, no. The ingest script was Postfix's delivery transport, so mail
went to Kafka instead of the mailbox. That's acceptable for a demo, not for
production. There are two options. **Inline**: score before delivery through
a milter, so phish never arrives, but every email now waits on the model and
you must decide whether to fail open or closed when the model is down.
**Post-delivery**: analyse a copy and pull bad mail out of mailboxes
afterwards; mail flow can never break, but there's a short window where the
user can see it. Behind an existing email gateway I'd choose post-delivery,
because a custom ML layer shouldn't be able to stop company email.
*Code: DESIGN §2, `deploy/postfix/README.md`*

### "What happens when Kafka is down?"
The PoC had a real bug here. It called `producer.send()` and `flush()` but
never checked the result, and kafka-python's `flush()` doesn't raise when a
send fails. So it could tell Postfix "done" while the email was lost. The fix
is to count success only when the broker's delivery report comes back with
no error. Otherwise exit with code 75, which tells Postfix "temporary
failure, keep it queued and retry." With `acks=all`, idempotence, and
`min.insync.replicas=2`, an acknowledged record survives a broker dying.
*Code: `producer.py`, `ingest.py`*

### "What if the model server is down?"
The worker doesn't commit offsets for that batch. It seeks back to the first
offset of the batch, backs off (0.5 s doubling to 30 s), and retries. Nothing
is skipped. Consumer lag grows while it waits, and that's what the alert
fires on.
*Code: `worker.py::_retry_later`*

### "What if one email crashes the worker?"
That's a poison pill. If you just retry, the same record crashes it again
and the partition is stuck forever. So when a batch fails with an unexpected
error, the worker re-scores the records one at a time. The one that fails
goes to a dead-letter topic with its original bytes, and the rest carry on.
Records that are invalid JSON, empty, or an unknown schema version go
straight to the DLQ.
*Code: `worker.py::_score`*

### "Is it exactly-once?"
No, at-least-once on purpose. Offsets are committed only after every verdict
is acknowledged, so if anything fails, the batch is reprocessed and you can
get duplicate verdicts. That's fine because verdicts are keyed by a message
hash and quarantining is idempotent: quarantining something twice does
nothing. Kafka transactions would make the consume→produce step exactly-once,
but not the whole system, since Postfix retries and mailbox actions happen
outside Kafka. So you need idempotency anyway, and the transactions would add
complexity for nothing.
*Code: `worker.py` module docstring, DESIGN §5*

### "Why not key by Message-ID?"
Message-ID is set by the sender. It isn't guaranteed unique, and an attacker
can reuse a legitimate email's ID, so their phish looks like a duplicate or
remediation pulls the wrong message. I key by the SHA-256 of the raw bytes:
it's stable across retries and can't be forged to collide. Message-ID is
still stored, because that's how you find the email in mailboxes.
*Code: `schema.py::EmailEvent.event_id`*

### "What if an email is too big for Kafka?"
Kafka's default message limit is about 1 MB, and emails with attachments go
over it. The raw email goes to object storage, and Kafka carries only a
reference plus the parsed fields (the claim-check pattern). Even the parsed
event can be too big, for example a long body in a non-Latin script, so it's
shrunk to fit. A record that's still too big is treated as a permanent
failure, not a retry, because retrying can't succeed. Postfix would retry
for days and then drop it silently.
*Code: `ingest.py::fit_event`, `blobstore.py`*

### "Is `is_phishing` a probability or a boolean?"
In the PoC it was ambiguous. If an upstream stage had already applied a
threshold it would be a boolean, and in Python `True > 0.85` is `True`, so
the code would run and the threshold would silently do nothing. The fix is
an explicit schema with separate fields: the model's raw score, the combined
score, and the action taken, plus the model version.
*Code: `schema.py::Verdict`*

### "Why 0.85?"
In the PoC it was arbitrary. Two things change. First, different actions get
different thresholds, because their mistakes cost different amounts: a
warning banner on a legitimate email is cheap, hiding one from someone is
expensive. So tag at a lower threshold and quarantine at a higher one.
Second, the thresholds come from data: run the evaluation, look at precision
and recall at each threshold, and choose based on what the business can
tolerate.
*Code: `decision.py`, `evaluate.py`*

### "What about HTML-only phishing?"
The PoC only read `text/plain` parts, so an HTML-only phish, which is most
of them, reached the model as an empty string. The parser now converts HTML
to text and also keeps each link's href *and* its visible text, because "the
text says paypal.com but the link goes to paypa1-secure.com" is one of the
strongest signals there is, and it disappears once you flatten HTML to text.
*Code: `parsing.py`*

### "What signals do you use besides the text?"
A body-text model can't see most of the strongest evidence. So there are
rules for:
- DMARC, SPF and DKIM failures, trusting only the authentication header our
  own mail server added, because attackers can add a fake one;
- a Reply-To that goes to a different domain;
- a display name that contains a different email address;
- links whose visible text and real destination differ;
- lookalike domains such as `paypa1` or `paypal-secure`;
- links to bare IP addresses;
- risky attachments such as `invoice.pdf.exe`.

These are combined with the model score using noisy-OR, so every verdict
comes with its reasons. Its weakness is that it double-counts correlated
signals, so with labelled data I'd replace it with a fitted, calibrated model.
*Code: `scoring/rules.py`, `scoring/combine.py`*

### "How do you know it works?"
Honestly, the PoC didn't: ground truth was attached to the synthetic emails
but never compared with the output. Now there's an evaluation that reports
precision, recall and false-positive rate at each threshold. Synthetic data
only proves the pipeline runs, because the test emails and the rules were
written by the same person. Real numbers need held-out labelled mail from
the organisation, re-measured over time because phishing changes.
*Code: `evaluate.py`*

### "Why use a GPU at this volume?"
For one company you may not need one. 10,000 employees is around a million
emails a day, about 12 a second on average and maybe 100 at peak, and BERT
on CPU with ONNX Runtime can plausibly handle that. A GPU with Triton earns
its cost at email-security-vendor volume, with bigger models, or when the
GPU is shared with other models. The model sits behind one interface, so
switching between GPU and CPU is a configuration choice. *(Back this up with
your own benchmark: CPU vs GPU throughput for your model.)*
*Code: `scoring/text_model.py`*

### "What would you alert on?"
The PoC only counted detections. I'd alert on: end-to-end latency, to catch
the pipeline falling behind; consumer lag; batch retries and DLQ growth,
which show quiet failures; and the quarantine rate compared with the same
time last week. A sudden jump there is either an attack wave or a broken
model, and both need a person.
*Code: `metrics.py`, `deploy/alerts.yml`*

### "What about privacy?"
Email bodies are sensitive, regulated data in a bank. That means:
- encryption in transit and at rest;
- per-service access control on topics, so ingest can only write and the
  worker can only read what it needs;
- retention set by policy, not by default;
- raw emails in access-logged storage;
- logs that contain only IDs and metadata, never email bodies.

*Code: DESIGN §11*

## What the evaluation numbers do and don't mean

On the synthetic corpus, the full pipeline separates phishing from legitimate
mail perfectly at a 0.5 threshold, while the keyword baseline alone catches about
a third of phishing. Read that as:

* **The rules add a lot over text alone.** The polite, urgency-free phish
  (mismatched links, spoofed internal sender) is invisible to a text-only
  scorer, which matches the main weakness of the PoC.
* **Perfect scores on synthetic data mean nothing about the real world.** The
  generator and the rules were written together from a small set of templates,
  so this is close to circular. Real numbers need held-out real mail.

## Status

| Part | State |
|---|---|
| Parsing, rules, policy, worker, evaluation | Implemented, unit tested |
| Kafka path (ingest → worker → verdict, broker-down, rewind after outage) | Tested end to end against librdkafka's in-process mock broker (no replication, so `acks=all` durability is not demonstrated) |
| Review | Independently reviewed; every finding fixed with a regression test (67 tests total) |
| `TritonTextScorer` | Written, **not run** against your model; check tensor names against `config.pbtxt` |
| `deploy/` (compose, Dockerfile, alerts) | YAML validated, **not run** here |
| Remediation service, schema registry, labelling loop, milter mode | Not implemented (described in DESIGN) |
