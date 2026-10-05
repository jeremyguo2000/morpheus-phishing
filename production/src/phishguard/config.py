"""Configuration from environment variables.

Everything that differed between machines in the PoC (broker address, Prometheus
target IP, conda paths, Grafana password) is a setting here instead of a literal
in code. Secrets are never given defaults: in production they come from a secret
manager injected as env vars, not from the repo.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default: str) -> str:
    return os.environ.get(f"PHISHGUARD_{name}", default)


def _env_list(name: str, default: str = "") -> tuple[str, ...]:
    raw = _env(name, default)
    return tuple(item.strip().lower() for item in raw.split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    # Kafka
    bootstrap_servers: str = field(default_factory=lambda: _env("BOOTSTRAP_SERVERS", "localhost:9092"))
    inbound_topic: str = field(default_factory=lambda: _env("INBOUND_TOPIC", "email-security"))
    verdict_topic: str = field(default_factory=lambda: _env("VERDICT_TOPIC", "output-email-classifications"))
    dlq_topic: str = field(default_factory=lambda: _env("DLQ_TOPIC", "email-security-dlq"))
    consumer_group: str = field(default_factory=lambda: _env("CONSUMER_GROUP", "phishguard-scorer"))

    # Claim-check storage for raw .eml bytes (S3 in production; a directory locally)
    blob_dir: str = field(default_factory=lambda: _env("BLOB_DIR", "/var/lib/phishguard/raw"))
    max_message_bytes: int = field(default_factory=lambda: int(_env("MAX_MESSAGE_BYTES", str(50 * 1024 * 1024))))

    # Only trust Authentication-Results headers stamped by *our* MTA (RFC 8601 authserv-id).
    trusted_authserv_ids: tuple[str, ...] = field(default_factory=lambda: _env_list("TRUSTED_AUTHSERV_IDS"))

    # Domains worth protecting against lookalikes (your company, banks, common SaaS).
    protected_domains: tuple[str, ...] = field(
        default_factory=lambda: _env_list(
            "PROTECTED_DOMAINS",
            "paypal.com,microsoft.com,office.com,google.com,apple.com,dbs.com.sg,ocbc.com,uob.com.sg",
        )
    )

    # Decision policy
    tag_threshold: float = field(default_factory=lambda: float(_env("TAG_THRESHOLD", "0.5")))
    quarantine_threshold: float = field(default_factory=lambda: float(_env("QUARANTINE_THRESHOLD", "0.85")))
    allowlisted_sender_domains: tuple[str, ...] = field(default_factory=lambda: _env_list("ALLOWLIST_DOMAINS"))

    # Model serving
    scorer: str = field(default_factory=lambda: _env("SCORER", "baseline"))  # "baseline" | "triton"
    triton_url: str = field(default_factory=lambda: _env("TRITON_URL", "localhost:8000"))
    triton_model: str = field(default_factory=lambda: _env("TRITON_MODEL", "phishing-bert-onnx"))

    # Worker
    batch_size: int = field(default_factory=lambda: int(_env("BATCH_SIZE", "64")))
    metrics_port: int = field(default_factory=lambda: int(_env("METRICS_PORT", "9033")))
