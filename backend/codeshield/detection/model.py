"""Optional CodeBERT detector with calibrated probabilities, CWE head, and attention rollout."""
from __future__ import annotations

import bisect
import json
import math
import threading
from dataclasses import dataclass, field
from typing import Any, Optional

from .. import config
from ..schemas import CodeUnit

_lock = threading.Lock()
_loaded: Optional["_Detector"] = None
_load_error: str = ""
_load_attempted = False


@dataclass
class ModelResult:
    probability: float
    available: bool = True
    label: str = "insecure"
    cwe_scores: dict[str, float] = field(default_factory=dict)


@dataclass
class TokenWeight:
    text: str
    weight: float
    line: int


@dataclass
class ModelAnalysis(ModelResult):
    tokens: list[TokenWeight] = field(default_factory=list)
    method: str = "attention-rollout"


class _Detector:
    def __init__(self) -> None:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self.torch = torch
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        local = config.DETECTION_MODEL_DIR
        source = str(local) if (local / "config.json").exists() else config.DETECTION_MODEL_ID
        if source == config.DETECTION_MODEL_ID and not (
            config.MODEL_MODE == "on" or config.ALLOW_MODEL_DOWNLOAD
        ):
            raise RuntimeError(
                "No local detector found. Run scripts/train_detector.py or set "
                "CODESHIELD_ALLOW_MODEL_DOWNLOAD=1."
            )
        self.source = source
        self.tokenizer = AutoTokenizer.from_pretrained(source)
        try:
            self.model = AutoModelForSequenceClassification.from_pretrained(
                source, attn_implementation="eager"
            )
        except (TypeError, ValueError):
            self.model = AutoModelForSequenceClassification.from_pretrained(source)
        self.model.to(self.device)
        self.model.eval()
        self.insecure_index = self._insecure_index()
        self.cwe_head = None
        self.cwe_labels: list[str] = []
        head_path = config.DETECTION_MODEL_DIR / "cwe_head.pt"
        labels_path = config.DETECTION_MODEL_DIR / "cwe_labels.json"
        if head_path.exists() and labels_path.exists():
            try:
                hidden = self.model.config.hidden_size
                head = torch.nn.Linear(hidden, len(json.loads(labels_path.read_text())))
                head.load_state_dict(torch.load(head_path, map_location=self.device))
                head.to(self.device).eval()
                self.cwe_head = head
                self.cwe_labels = json.loads(labels_path.read_text())
            except Exception:
                self.cwe_head = None

    def _insecure_index(self) -> int:
        labels = getattr(self.model.config, "id2label", {}) or {}
        for index, label in labels.items():
            text = str(label).lower()
            if any(token in text for token in ("insecure", "vulnerable", "bad", "true")):
                return int(index)
        return 1 if self.model.config.num_labels > 1 else 0

    def _inputs(self, text: str, offsets: bool = False):
        kwargs = {
            "return_tensors": "pt",
            "truncation": True,
            "max_length": config.MODEL_MAX_TOKENS,
            "padding": True,
        }
        if offsets:
            kwargs["return_offsets_mapping"] = True
        encoded = self.tokenizer(text, **kwargs)
        return {k: v.to(self.device) for k, v in encoded.items() if k in {"input_ids", "attention_mask", "token_type_ids"}}

    def _probability(self, text: str) -> float:
        inputs = self._inputs(text)
        with self.torch.no_grad():
            logits = self.model(**inputs).logits
            if logits.shape[-1] == 1:
                raw = float(self.torch.sigmoid(logits[0, 0]))
            else:
                raw = float(self.torch.softmax(logits, dim=-1)[0, self.insecure_index])
        if raw <= 0 or raw >= 1:
            return raw
        logit = math.log(raw / (1 - raw))
        calibrated = 1 / (1 + math.exp(-(config.CALIBRATION_A * logit + config.CALIBRATION_B)))
        return max(0.0, min(1.0, calibrated))

    def _cwe_scores(self, text: str) -> dict[str, float]:
        if self.cwe_head is None:
            return {}
        inputs = self._inputs(text)
        with self.torch.no_grad():
            outputs = self.model(**inputs, output_hidden_states=True)
            hidden = outputs.hidden_states[-1][:, 0, :]
            logits = self.cwe_head(hidden)[0]
            probs = self.torch.sigmoid(logits).tolist()
        return {label: float(p) for label, p in zip(self.cwe_labels, probs)}

    def analyze(self, text: str) -> ModelAnalysis:
        inputs_offsets = self.tokenizer(
            text, return_tensors="pt", truncation=True, max_length=config.ATTENTION_MAX_TOKENS,
            return_offsets_mapping=True,
        )
        offsets = inputs_offsets.pop("offset_mapping")[0].tolist()
        inputs = {k: v.to(self.device) for k, v in inputs_offsets.items() if k in {"input_ids", "attention_mask", "token_type_ids"}}
        with self.torch.no_grad():
            outputs = self.model(**inputs, output_attentions=True)
            logits = outputs.logits
            if logits.shape[-1] == 1:
                raw = float(self.torch.sigmoid(logits[0, 0]))
            else:
                raw = float(self.torch.softmax(logits, dim=-1)[0, self.insecure_index])
            attentions = outputs.attentions
            weights = None
            if attentions:
                rollout = None
                for attention in attentions:
                    matrix = attention[0].mean(dim=0)
                    matrix = matrix + self.torch.eye(matrix.shape[0], device=matrix.device)
                    matrix = matrix / matrix.sum(dim=-1, keepdim=True)
                    rollout = matrix if rollout is None else matrix @ rollout
                if rollout is not None:
                    weights = rollout[0].detach().float().cpu().tolist()
        if raw <= 0 or raw >= 1:
            probability = raw
        else:
            logit = math.log(raw / (1 - raw))
            probability = 1 / (1 + math.exp(-(config.CALIBRATION_A * logit + config.CALIBRATION_B)))
        ids = inputs["input_ids"][0].detach().cpu().tolist()
        tokens: list[TokenWeight] = []
        line_starts = [0]
        for index, char in enumerate(text):
            if char == "\n":
                line_starts.append(index + 1)
        if weights is not None:
            for position, (start, end) in enumerate(offsets):
                if end <= start or position >= len(weights):
                    continue
                token_text = text[start:end]
                if not token_text.strip():
                    continue
                line = bisect.bisect_right(line_starts, start)
                tokens.append(TokenWeight(text=token_text, weight=float(weights[position]), line=line))
            if tokens:
                maximum = max(t.weight for t in tokens) or 1.0
                for token in tokens:
                    token.weight = token.weight / maximum
        elif ids:
            for position, token_id in enumerate(ids):
                piece = self.tokenizer.decode([token_id], skip_special_tokens=True)
                if piece.strip():
                    tokens.append(TokenWeight(text=piece, weight=0.0, line=1))
        return ModelAnalysis(
            probability=max(0.0, min(1.0, probability)), tokens=tokens,
            cwe_scores=self._cwe_scores(text), method="attention-rollout" if weights else "tokens-only",
        )


def _get_detector() -> Optional[_Detector]:
    global _loaded, _load_error, _load_attempted
    if config.MODEL_MODE == "off":
        return None
    if _load_attempted:
        return _loaded
    with _lock:
        if _load_attempted:
            return _loaded
        try:
            _loaded = _Detector()
            _load_error = ""
        except Exception as exc:
            _loaded = None
            _load_error = str(exc)[:400]
        _load_attempted = True
    return _loaded


def predict(unit: CodeUnit) -> Optional[ModelResult]:
    detector = _get_detector()
    if detector is None:
        return None
    try:
        with _lock:
            probability = detector._probability(unit.source)
            scores = detector._cwe_scores(unit.source)
        return ModelResult(
            probability=probability,
            cwe_scores={k: v for k, v in sorted(scores.items(), key=lambda kv: -kv[1])[:5]},
        )
    except Exception:
        return None


def analyze(unit: CodeUnit) -> Optional[ModelAnalysis]:
    detector = _get_detector()
    if detector is None:
        return None
    try:
        with _lock:
            return detector.analyze(unit.source)
    except Exception:
        return None


def status() -> dict[str, Any]:
    detector = _get_detector()
    if config.MODEL_MODE == "off":
        return {"mode": "off", "available": False, "reason": "disabled by configuration"}
    if detector is None:
        return {
            "mode": config.MODEL_MODE, "available": False,
            "reason": _load_error or "model not loaded", "model_id": config.DETECTION_MODEL_ID,
        }
    return {
        "mode": config.MODEL_MODE,
        "available": True,
        "model_id": detector.source,
        "device": detector.device,
        "cwe_head": detector.cwe_head is not None,
        "insecure_index": detector.insecure_index,
    }
