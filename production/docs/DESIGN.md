# Phishing detection: from PoC to production

This document describes what the Morpheus phishing PoC (repository root) would
need to become a production system, and records the reasoning behind each
change. The code in `production/` is a reference implementation of the parts
that don't need a GPU. Read this first, then the code in the order given in
`src/phishguard/__init__.py`.

## 1. Where the PoC stands

The PoC proved the components connect: Postfix → Python parser → Kafka →
Morpheus (BERT on Triton) → Kafka → Prometheus counter → Grafana. That was its
purpose. It is a demo, not a system, because:

| Area | PoC behaviour | Consequence |
|---|---|---|
| Mail flow | Ingest script was the Postfix delivery transport | Mail went to Kafka and never reached the mailbox; nothing could be blocked or remediated |
| Delivery guarantees | `producer.send()` result never checked; `flush()` doesn't raise | Script could exit 0 while the record was lost |
| Parsing | Only `text/plain`; recipients split on commas | HTML-only phish scored as an empty string; recipient counts wrong |
| Signals | Body text only | Missed SPF/DKIM/DMARC, Reply-To, link mismatches, lookalikes, attachments |
| Decision | One 0.85 threshold inside a metrics consumer | No action taken; threshold not chosen from data |
| Evaluation | Ground truth attached, never compared | No evidence the model works |
| Kafka | One broker, no volume, RF 1 | Restart lost unconsumed data |
| Operations | Hard-coded IPs, paths, `admin` password | Not deployable anywhere but one machine |

## 2. The main design decision: block before delivery, or remediate after?

Most of the architecture follows from this choice.

**Inline (pre-delivery).** Scoring runs on the delivery path through a milter or
an after-queue content filter. Phish never reaches the inbox. The costs:

* A hard latency budget (seconds at most), since every email waits for a verdict.
* An explicit **fail-open vs fail-closed** decision for when the model is down.
  Fail-closed stops company mail when Triton fails. Fail-open lets phish
  through during outages. Banks usually fail open with alerting, plus a
  secure email gateway in front that keeps blocking known-bad mail.
* Batching for GPU efficiency fights the latency budget.

**Post-delivery (asynchronous).** A copy of each message is analysed and
malicious ones are pulled from mailboxes afterwards (Graph API on M365, or
equivalent). The costs:

* A window, usually seconds to minutes, in which the user can see and click the phish.
* Remediation must be reliable and idempotent.

**Choice for this reference: post-delivery**, as a layer behind an existing
secure email gateway. That is how a custom ML detector is realistically
deployed in an enterprise. It can't break mail flow, it can use heavier
models, and Kafka's buffering and replay are real advantages here. The inline
path is documented in `deploy/postfix/README.md` as the next step.

## 3. Architecture

```
 MTA / M365 journaling
        │  copy of each inbound message
        ▼
 ingest ── raw .eml ──► object storage (claim-check, encrypted, retention policy)
        │  parsed EmailEvent + raw_ref, key = event_id (SHA-256 of raw bytes)
        ▼
 Kafka: email-security ─────────────► (other consumers: archiving, analytics…)
        │
        ▼
 worker (consumer group, N replicas)
   parse check ─► rules ─► text model (Triton, batched) ─► combine ─► policy
        │                                      │
        │ verdict (key = event_id)             │ bad records
        ▼                                      ▼
 Kafka: output-email-classifications     Kafka: email-security-dlq
        │
        ├─► remediation service (quarantine via mail API, idempotent)
        ├─► SIEM / SOC alerting
        └─► label store ◄── user "report phish" + analyst decisions ──► retraining / evaluation
```

Each box can scale and fail on its own, and Kafka sits between them.

## 4. Data contracts

`schema.py` defines a versioned `EmailEvent` and `Verdict`. Rules:

* Every record carries `schema_version`. A consumer that sees an unknown
  version sends the record to the DLQ and does not guess.
* In production these become Avro/Protobuf schemas in a schema registry, with
  compatibility enforced at publish time.
* Records are keyed by **event_id, the SHA-256 of the raw bytes**, not by
  Message-ID. Message-ID is chosen by the sender, isn't guaranteed unique,
  and a phish can reuse a legitimate message's ID, which would make it look
  like a "duplicate" or point remediation at the wrong message. The hash is
  stable across retries of the same delivery, so duplicates are easy to spot.
  Message-ID is still recorded, because it's how you find the message in
  mailboxes.
* Raw bytes go to object storage (claim-check). Kafka's default ~1 MB message
  limit is easily exceeded by attachments, and most consumers don't need them.
  The *event* can still be too big (a long non-Latin body), so ingest
  serializes UTF-8 without escapes and shrinks the body until it fits under
  900 KB. Nothing is lost permanently, because the full message is in storage.

## 5. Delivery semantics and failure handling

The system is **at-least-once** end to end:

| Step | Guarantee | Mechanism |
|---|---|---|
| Postfix → ingest | Retry until accepted | Exit 75 (`EX_TEMPFAIL`) on any storage/Kafka failure *or crash* keeps the copy queued; only 0/65/75 are ever returned |
| ingest → Kafka | Acked = durable | `acks=all`, idempotent producer, success only after a delivery report |
| Kafka → worker → Kafka | No loss, possible duplicates | Manual commit only after all outputs of a batch are acked; otherwise seek back and retry |
| Verdict → remediation | Idempotent | Quarantining an already-quarantined message is a no-op |

Duplicates are the deliberate trade-off. Kafka transactions plus
`read_committed` consumers would make the worker's consume→produce step
exactly-once, but not the whole system: Postfix retries at ingest and side
effects outside Kafka (quarantining) still need idempotency. Here that's
cheap, so at-least-once plus idempotent consumers is the right trade.

Failure modes:

| Failure | Behaviour |
|---|---|
| Kafka down during ingest | Exit 75; Postfix retries. Mail delivery unaffected (copy path). |
| Ingest crashes (bad deploy, config error) | Exit 75, never 1: any other non-zero status is a hard bounce, and a BCC copy bounces *silently*. |
| Event too large even after shrinking | Exit 65 (permanent) and an ERROR log. Retrying can't help; as a TEMPFAIL Postfix would retry for days and then drop it silently. Alert on these logs. |
| Malformed email | Parser never raises; event carries `parse_warnings` and is still scored. |
| Record with unknown schema / invalid JSON / null value | DLQ with the original bytes (base64) for replay. Batch continues. |
| Record that crashes scoring (poison pill) | Batch is re-scored one record at a time; the bad record goes to the DLQ. |
| Triton down / timing out | `ScorerUnavailable` → seek back, exponential backoff (0.5 s → 30 s), retry. Lag grows and alerts fire. |
| Verdict produce not acked | Seek back and retry the batch; no commit. |
| Worker killed mid-batch | Uncommitted batch is re-read by whichever worker owns the partition next. |
| Commit fails (rebalance), whole or per partition | Logged; new owner reprocesses from last commit (duplicates, not loss). |

## 6. Detection

The PoC used one signal, a BERT classifier over the body text. Production
combines independent evidence:

| Signal | Why it matters | Where |
|---|---|---|
| DMARC / SPF / DKIM failures | Sender is not who they claim | `rules._auth` |
| Trusted `Authentication-Results` only | Attackers can add their own `dmarc=pass` header. Only as safe as the MTA: it must strip incoming headers carrying its own authserv-id (RFC 8601 §5), and every intake path must pass through it | `parsing.parse_auth_results` |
| Reply-To ≠ From domain | Classic BEC / CEO-fraud pattern | `rules._reply_to` |
| Display name contains another address | `"ceo@company.com" <x@freemail>` | `rules._display_name` |
| Link text domain ≠ href domain | Visible text says paypal.com, link goes elsewhere | `rules._links` |
| Lookalike domains | `paypa1-secure.com`, `paypall.com`, `paypal-secure.com` | `rules._lookalike` |
| Links to bare IPs | Rare in legitimate mail | `rules._links` |
| Risky / double-extension attachments | `invoice.pdf.exe` | `rules._attachments` |
| Text model | Social-engineering language rules can't capture | `scoring/text_model.py` |

**Combination.** Noisy-OR (`scoring/combine.py`) is a transparent starting
point: any strong signal can push the score up on its own, weak signals add
up, and every factor becomes a `Reason` in the verdict. Its known flaw is
that correlated signals (SPF fail and DMARC fail) get double-counted. Once
labelled data exists, the next step is a fitted model (logistic regression
over the same signals plus the model score) with calibration, so that 0.9
really means about 90%.

**Text model notes.**
* Subject + body go to the model. The PoC sent only the body. When the plain
  and HTML alternatives say different things, both go in, because the HTML is
  what the recipient actually sees.
* BERT truncates (often at 128 tokens). A link at the bottom of a long email
  may never reach the model, which is one reason the link rules exist.
* The model is served behind the `TextScorer` interface, so Triton, CPU ONNX
  Runtime and test stubs are interchangeable.
* GPU serving pays off with volume and batching. At low volume, CPU ONNX
  Runtime is simpler and cheaper. Measure before choosing.
* New model versions run in **shadow mode** (scored and logged, never acted
  on) and are compared with the live model before promotion. Every verdict
  records `model_name` and `model_version`.

## 7. Decision policy

`decision.py` separates the score from the action:

* **Tag** (banner/header): cheap false positive, so a lower threshold (default 0.5).
* **Quarantine**: an expensive false positive (a hidden legitimate email), so a
  higher threshold (default 0.85).
* Thresholds are set from the evaluation table (§9) based on what the
  business can accept, then reviewed whenever metrics move.
* **Allowlisting is dangerous**: attackers spoof allowlisted senders. An
  allowlisted domain bypasses only when DMARC passed and that result came from
  our own MTA.

## 8. Infrastructure

| Component | Local (`deploy/docker-compose.yaml`) | Production |
|---|---|---|
| Kafka | 1 broker, persistent volume | ≥3 brokers across zones, RF 3, `min.insync.replicas=2`, TLS + SASL, ACLs per service |
| Topics | 6 partitions, 7-day retention | Partitions sized to peak throughput ÷ per-consumer throughput, with headroom; retention set by data-protection policy |
| Raw storage | Local directory | Object storage, server-side encryption, lifecycle deletion, access logged |
| Worker | 1 container | Kubernetes Deployment, replicas ≤ partitions, autoscaled on consumer lag (e.g. KEDA) |
| Model serving | Baseline heuristic | Triton (or ONNX Runtime) with dynamic batching, versioned model repository |
| Secrets | Env var, no defaults | Secret manager → env/volume; no credentials in the repo |

Throughput sizing example: at 50 emails/s peak, with one worker scoring ~200/s
in batches of 64, one replica is enough on paper. Run 3 or more for availability,
which means at least 3 partitions. Re-measure with the real model.

## 9. Evaluation

`evaluate.py` joins ground truth with scores and reports precision, recall,
false-positive rate and F1 across thresholds. Run it on:

1. **Synthetic data** (`phishguard synth`) to check the plumbing. The
   generator includes hard cases (polite phish with mismatched links, spoofed
   internal senders with no urgency, legitimate IT mail that *says* "reset your
   password within 24 hours"), but it is still synthetic and says nothing about
   real-world accuracy.
2. **Public corpora** for a first real-world estimate.
3. **A held-out set of the organisation's own labelled mail.** This is the only
   number that matters, and it has to be re-measured as phishing evolves.

Run `--model-only` alongside the full pipeline to see what the rules add.

## 10. Observability

Worker metrics (`metrics.py`) and alert rules (`deploy/alerts.yml`):

* End-to-end latency histogram (ingest → verdict). Are we keeping up?
* Consumer lag (from a Kafka exporter). Are we falling behind?
* Batch retries and DLQ counts. Are we failing quietly?
* Score distribution and quarantine rate compared with last week. A sudden
  shift means either an attack wave or a broken model, and both need a person.
* Model name/version info. Which model produced these numbers?

Logs are structured (JSON). Message-ID works as a trace ID across ingest,
worker, remediation and the SIEM.

## 11. Security and privacy

Email bodies are sensitive data, and in a bank regulated data.

* Encryption in transit (Kafka TLS) and at rest (broker disks, object storage).
* Per-service ACLs: ingest can only write the inbound topic; the worker
  reads inbound and writes verdict/DLQ.
* Topic retention and object lifecycle rules set by data-protection policy, not defaults.
* Access to raw messages is logged; analysts see them only through the review tool.
* Logs never contain bodies, only Message-ID and metadata.
* Parser hardening: size caps, body truncation, link caps, no attachment execution.

## 12. What the reference implements and what it doesn't

Implemented and tested (67 tests, including end-to-end over the Kafka
protocol with librdkafka's in-process mock broker, which covers produce,
consumer groups, seek and commits but not replication). The code was
independently reviewed and the findings fixed, each with a regression test:
ingest with Postfix-correct exit codes, claim-check storage, confirmed
delivery, robust MIME parsing, rules, baseline scorer, noisy-OR combination,
policy, batch worker with at-least-once commits, DLQ, poison-pill isolation,
backoff, metrics, evaluation, harder synthetic corpus.

Written but not run against real infrastructure:
* `TritonTextScorer`: tensor names and output format depend on how the model
  was exported. Check them against the model's `config.pbtxt`.
* `deploy/docker-compose.yaml`, `Dockerfile`, alerts: YAML validated, not run here.

Not implemented: the remediation service, schema registry integration, user
report and labelling loop, model training, inline (milter) mode, Kubernetes
manifests.

Known limitation of the Postfix copy path: the BCC copy's envelope recipient
is the pipeline's own address, so the original envelope recipients, including
Bcc'd victims (common in phishing campaigns), are lost. Remediation would have
to search all mailboxes by Message-ID (the Graph API can do this), or intake
should use journaling or a milter, both of which see every envelope recipient.
That's another reason journaling is the production intake for M365.
