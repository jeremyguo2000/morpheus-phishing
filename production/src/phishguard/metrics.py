"""Prometheus metrics.

The PoC exported one counter (phishing vs non-phishing). That answers "how many
did we flag" but none of the questions you get paged for:

  * Is it keeping up?           -> end-to-end latency histogram, plus consumer lag
                                   (lag comes from a Kafka exporter such as
                                   kafka-exporter/Burrow, not from the app itself)
  * Is it failing silently?     -> DLQ and retry counters
  * Did the model change?       -> model version info + score distribution
                                   (a shifted distribution is the cheapest drift alarm)

Example alerts (PromQL) are in deploy/alerts.yml.
"""

from __future__ import annotations

from prometheus_client import Counter, Histogram, Info

VERDICTS = Counter("phishguard_verdicts_total", "Verdicts produced", ["action"])
DLQ = Counter("phishguard_dlq_total", "Records sent to the dead-letter topic", ["reason"])
BATCH_RETRIES = Counter("phishguard_batch_retries_total", "Batches rewound and retried", ["cause"])
END_TO_END = Histogram("phishguard_end_to_end_seconds", "Ingest-to-verdict latency",
                       buckets=(0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 300))
BATCH_SECONDS = Histogram("phishguard_batch_seconds", "Time to process one consumed batch",
                          buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10))
SCORE = Histogram("phishguard_score", "Combined score distribution",
                  buckets=(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95, 1.0))
MODEL = Info("phishguard_model", "Model currently used for scoring")
