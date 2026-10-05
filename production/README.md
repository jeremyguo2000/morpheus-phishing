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

## Interview questions → where they're answered

| Question | Answer lives in |
|---|---|
| "Does the user still get their email?" | `docs/DESIGN.md` §2, `deploy/postfix/README.md` |
| "What happens when Kafka is down?" | `producer.py`, `ingest.py`, `test_ingest_and_producer.py` |
| "What if the model server is down?" | `worker.py::_retry_later`, `test_scorer_down_rewinds_and_does_not_commit` |
| "What if one email crashes the worker?" | `worker.py::_score`, `test_poison_pill_is_isolated_and_the_rest_proceed` |
| "Exactly-once?" | `worker.py` module docstring, DESIGN §5 |
| "Why not key by Message-ID?" | `schema.py::EmailEvent.event_id`, DESIGN §4 |
| "What if an email is too big for Kafka?" | `ingest.py::fit_event`, `producer.py::RecordTooLarge` |
| "Is `is_phishing` a probability or a bool?" | `schema.py::Verdict` (separate `score`, `action`, `model_score`) |
| "Why 0.85?" | `decision.py`, `evaluate.py`, DESIGN §7 and §9 |
| "HTML-only phishing?" | `parsing.py`, `test_html_only_email_still_has_text_and_links` |
| "What signals besides text?" | `scoring/rules.py`, DESIGN §6 |
| "How do you know it works?" | `evaluate.py`, DESIGN §9 |
| "Why GPU for this volume?" | DESIGN §6 (text model notes) and §8 |
| "What do you alert on?" | `metrics.py`, `deploy/alerts.yml` |
| "Privacy?" | DESIGN §11 |

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
