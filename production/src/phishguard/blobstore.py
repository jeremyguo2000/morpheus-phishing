"""Claim-check storage for raw messages.

Kafka's default max message size is ~1 MB. Emails with attachments regularly
exceed that, and you rarely want full attachment bytes flowing through every
consumer anyway. The claim-check pattern: store the raw bytes once (S3 / object
storage in production, with encryption and a retention policy), and put only a
reference plus the parsed metadata on the topic.

Keys are content hashes, so writing the same message twice (a retried Postfix
delivery) is idempotent.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path
from typing import Protocol


class BlobStore(Protocol):
    def put(self, data: bytes) -> str: ...
    def get(self, ref: str) -> bytes: ...


class LocalBlobStore:
    """Directory-backed store. Writes are atomic: temp file + rename, so a crash
    mid-write never leaves a truncated object that a consumer could read."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, data: bytes) -> str:
        digest = hashlib.sha256(data).hexdigest()
        path = self.root / digest[:2] / f"{digest}.eml"
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, path)
            except BaseException:
                Path(tmp).unlink(missing_ok=True)
                raise
        return f"file://{path}"

    def get(self, ref: str) -> bytes:
        if not ref.startswith("file://"):
            raise ValueError(f"not a local blob ref: {ref}")
        path = Path(ref[len("file://"):]).resolve()
        if self.root.resolve() not in path.parents:
            raise ValueError("blob ref outside store root")
        return path.read_bytes()
