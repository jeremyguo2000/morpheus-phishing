"""phishguard: a production-shaped reference for the Morpheus phishing PoC.

Module map (read in this order):
    schema.py      the contract between stages (versioned event + verdict)
    parsing.py     raw RFC 5322 bytes -> EmailEvent, never raises
    blobstore.py   claim-check storage for raw messages
    producer.py    Kafka producer that only reports success after the broker acks
    ingest.py      the Postfix pipe entry point, with exit codes Postfix understands
    scoring/       rules + text model + combination into one explainable score
    decision.py    score -> action (allow / tag / quarantine), with allowlist safety
    worker.py      consume -> score -> produce -> commit, with DLQ and safe retries
    evaluate.py    precision / recall against ground truth
    metrics.py     Prometheus metrics
    cli.py         `phishguard score|ingest|worker|evaluate`
"""

__version__ = "0.1.0"
