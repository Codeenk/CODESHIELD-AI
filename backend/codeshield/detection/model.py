"""Optional CodeBERT classifier wrapper.

Wraps ``mrm8488/codebert-base-finetuned-detect-insecure-code`` — a *binary*
insecure/secure classifier — behind a tiny interface. Loading is lazy and every
failure degrades to ``available == False`` so the rule engine alone keeps the
scanner working (no network, no GPU, no transformers, no problem).
"""
from __future__ import annotations

import logging
from typing import Optional, Sequence

from .. import config

log = logging.getLogger("codeshield.model")


class _BaseDetector:
    name = "none"
    enabled = False
    available = False

    def predict_proba(self, texts: Sequence[str]) -> list[Optional[float]]:
        return [None for _ in texts]

    def warmup(self) -> bool:  # pragma: no cover - trivial
        return False


class NullDetector(_BaseDetector):
    """Used when the model is disabled or unavailable."""


class CodeBertDetector(_BaseDetector):
    """Lazy wrapper around the fine-tuned CodeBERT binary classifier."""

    name = "codebert-insecure-code"

    def __init__(self, model_id: Optional[str] = None, mode: Optional[str] = None) -> None:
        self.model_id = model_id or config.DETECTION_MODEL_ID
        self.mode = (mode or config.MODEL_MODE).lower()
        self.enabled = self.mode in {"auto", "on"}
        self.available = False
        self._tokenizer = None
        self._model = None
        self._torch = None
        self._failed = False
        self._max_tokens = config.MODEL_MAX_TOKENS

    def _ensure_loaded(self) -> bool:
        if self.available:
            return True
        if not self.enabled or self._failed:
            return False
        try:
            import torch  # type: ignore
            from transformers import AutoModelForSequenceClassification, AutoTokenizer  # type: ignore

            self._tokenizer = AutoTokenizer.from_pretrained(self.model_id)
            self._model = AutoModelForSequenceClassification.from_pretrained(self.model_id)
            self._model.eval()
            self._torch = torch
            self.available = True
            log.info("Loaded detection model %s", self.model_id)
        except Exception as exc:  # noqa: BLE001 - degrade for any reason
            self._failed = True
            self.available = False
            log.warning("Detection model unavailable (%s: %s); rules only", type(exc).__name__, exc)
            if self.mode == "on":
                raise
        return self.available

    def warmup(self) -> bool:
        return self._ensure_loaded()

    def predict_proba(self, texts: Sequence[str]) -> list[Optional[float]]:
        if not self._ensure_loaded():
            return [None for _ in texts]
        probs: list[Optional[float]] = []
        batch_size = 8
        torch = self._torch
        assert torch is not None
        for start in range(0, len(texts), batch_size):
            chunk = list(texts[start : start + batch_size])
            try:
                enc = self._tokenizer(
                    chunk,
                    return_tensors="pt",
                    truncation=True,
                    padding=True,
                    max_length=self._max_tokens,
                )
                with torch.no_grad():
                    logits = self._model(**enc).logits
                softmax = torch.softmax(logits, dim=-1)
                # Label 1 == insecure code.
                risky = softmax[:, -1].tolist()
                probs.extend(float(v) for v in risky)
            except Exception as exc:  # noqa: BLE001
                log.warning("Inference failed (%s); skipping batch", exc)
                probs.extend([None] * len(chunk))
        return probs


def build_detector(mode: Optional[str] = None) -> _BaseDetector:
    mode = (mode or config.MODEL_MODE).lower()
    if mode == "off":
        return NullDetector()
    return CodeBertDetector(mode=mode)
