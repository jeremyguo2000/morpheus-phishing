"""Text model interface.

`TextScorer` is the seam between the pipeline and model serving. The worker
only depends on this interface, so you can swap Triton for a CPU ONNX Runtime
session, or a stub in tests, without touching pipeline code.

Two implementations:

* BaselineKeywordScorer: a deliberately simple keyword heuristic so the whole
  pipeline runs on a laptop with no GPU. It is NOT a model; use it to exercise
  the plumbing and as a floor to beat in evaluation.

* TritonTextScorer: calls a BERT-style classifier on Triton (like the PoC's
  `phishing-bert-onnx`). Tensor names, sequence length and output handling are
  configurable because they depend on how the model was exported. This class
  has NOT been run against your model in this repo; check the names against
  the model's config.pbtxt before relying on it.
"""

from __future__ import annotations

import math
import re
from typing import Protocol, Sequence


class ScorerUnavailable(RuntimeError):
    """Model serving is down or timed out. Retryable: the worker rewinds and retries the batch."""


class TextScorer(Protocol):
    name: str
    version: str

    def score_batch(self, texts: Sequence[str]) -> list[float]:
        """Return P(phishing) in [0, 1] for each text, same order."""
        ...


class BaselineKeywordScorer:
    name = "baseline-keywords"
    version = "1"

    _PATTERNS = [re.compile(p, re.IGNORECASE) for p in (
        r"verify (your )?(account|identity|details)",
        r"(account|access) (will be )?(suspended|terminated|locked|disabled)",
        r"within \d+ hours",
        r"(urgent|immediate) (action|attention)",
        r"confirm (your )?(identity|password|details)",
        r"(reset|update) (your )?password",
        r"unusual (sign-?in|login|activity)",
        r"click (the )?(link|below|here)",
    )]

    def score_batch(self, texts: Sequence[str]) -> list[float]:
        scores = []
        for text in texts:
            hits = sum(1 for p in self._PATTERNS if p.search(text or ""))
            scores.append(min(0.9, 0.2 * hits))
        return scores


class TritonTextScorer:
    """BERT classifier on Triton over HTTP. Requires the `triton` extra."""

    def __init__(self, url: str, model: str, *, tokenizer: str = "bert-base-uncased",
                 max_length: int = 128, input_ids: str = "input_ids", attention_mask: str = "attention_mask",
                 output: str = "output", output_kind: str = "logits", positive_index: int = 1,
                 timeout_s: float = 5.0):
        # output_kind is explicit because it can't be guessed: a single value of 0.0 is
        # P=0.0 if the model ends in a sigmoid, but P=0.5 if it is a raw logit.
        if output_kind not in ("logits", "probabilities"):
            raise ValueError("output_kind must be 'logits' or 'probabilities'")
        self._kind = output_kind
        import numpy as np
        import tritonclient.http as httpclient
        from transformers import AutoTokenizer

        self._np, self._http = np, httpclient
        self._client = httpclient.InferenceServerClient(url=url, connection_timeout=timeout_s,
                                                        network_timeout=timeout_s)
        self._tok = AutoTokenizer.from_pretrained(tokenizer)
        self.name, self._model = model, model
        self._max_length, self._in_ids, self._in_mask = max_length, input_ids, attention_mask
        self._out, self._pos = output, positive_index
        try:
            meta = self._client.get_model_metadata(model)
            self.version = str(meta.get("versions", ["unknown"])[-1])
        except Exception as exc:
            raise ScorerUnavailable(f"cannot reach Triton model {model}: {exc}") from exc

    def score_batch(self, texts: Sequence[str]) -> list[float]:
        if not texts:
            return []
        # NB: truncation at max_length tokens means a link at the bottom of a long email
        # may never reach the model; the link rules exist partly to cover that blind spot.
        enc = self._tok(list(texts), padding="max_length", truncation=True,
                        max_length=self._max_length, return_tensors="np")
        inputs = []
        for name, arr in ((self._in_ids, enc["input_ids"]), (self._in_mask, enc["attention_mask"])):
            tensor = self._http.InferInput(name, arr.shape, "INT64")
            tensor.set_data_from_numpy(arr.astype(self._np.int64))
            inputs.append(tensor)
        try:
            result = self._client.infer(self._model, inputs,
                                        outputs=[self._http.InferRequestedOutput(self._out)])
        except Exception as exc:
            status_fn = getattr(exc, "status", None)  # tritonclient's InferenceServerException.status()
            status = str(status_fn() or "") if callable(status_fn) else ""
            if status.startswith("4"):
                # The server rejected THIS input (HTTP 4xx). Retrying can't help; raising a plain
                # error lets the worker isolate the record into the DLQ instead of rewinding forever.
                raise ValueError(f"Triton rejected input ({status}): {exc}") from exc
            raise ScorerUnavailable(f"Triton inference failed: {exc}") from exc
        outputs = result.as_numpy(self._out)
        return [self._to_probability(row) for row in outputs]

    def _to_probability(self, row) -> float:
        values = [float(v) for v in (row if hasattr(row, "__len__") else [row])]
        if self._kind == "probabilities":
            return values[self._pos] if len(values) > 1 else values[0]
        if len(values) == 1:  # single logit -> sigmoid
            return 1 / (1 + math.exp(-values[0]))
        m = max(values)  # softmax over class logits, numerically stable
        exps = [math.exp(v - m) for v in values]
        return exps[self._pos] / sum(exps)


def build_scorer(kind: str, *, triton_url: str = "", triton_model: str = "") -> TextScorer:
    if kind == "baseline":
        return BaselineKeywordScorer()
    if kind == "triton":
        return TritonTextScorer(triton_url, triton_model)
    raise ValueError(f"unknown scorer {kind!r}")
