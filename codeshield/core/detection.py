"""Stage 3 — vulnerability detection (PRD §7.3, §11.1).

Two engines run and their results are merged:

* **CodeBERTDetector** — ``mrm8488/codebert-base-finetuned-detect-insecure-code``, a binary
  function-level classifier (``LABEL_0`` secure / ``LABEL_1`` insecure). Loaded lazily so the
  MVP runs with no GPU; if torch/transformers or the weights are unavailable the pipeline
  degrades gracefully and records *why* in ``engine_notes``.
* **rules.scan_text** — the rule-based baseline (see ``rules.py``).

Agreement raises confidence (``Engine.both``); a model hit with no rule support is reported
as ``Engine.model`` and labelled for review (PRD §1.1).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..config import Settings, get_settings
from ..models import AttentionLine, Engine, Finding, Location, Severity
from . import rules as rules_mod
from .parsing import FileAnalysis, FunctionUnit, analyze_file, snippet_for
from .severity import cwe_info, severity_for

# Keyword heuristics used only to *label* a model-only finding with a likely CWE class.
_CWE_HINTS: list[tuple[str, re.Pattern]] = [
    ("CWE-89", re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b.*(?:execute|query)|\bsql\b", re.I)),
    ("CWE-78", re.compile(r"\b(?:system|popen|exec|ProcessBuilder|Runtime)\b")),
    ("CWE-79", re.compile(r"\b(?:innerHTML|document\.write|getParameter)\b")),
    ("CWE-502", re.compile(r"\b(?:pickle|unpickle|ObjectInputStream|readObject|yaml\.load)\b")),
    ("CWE-22", re.compile(r"\b(?:\.\./|FileInputStream|open\()")),
    ("CWE-918", re.compile(r"\b(?:urlopen|requests?\.(?:get|post)|HttpURLConnection)\b")),
    ("CWE-327", re.compile(r"\b(?:DES|RC4|MD5|SHA1)\b")),
]


def model_only_severity(cwe: str, confidence: float) -> Severity:
    """Severity cap for an unconfirmed, model-only finding.

    Measured behaviour (``scripts/eval_model.py``): the off-the-shelf checkpoint flags most
    *clean* functions as insecure at ~0.99, i.e. it is not discriminative on its own (MCC 0.00
    on the smoke set). A model hit with no rule support is therefore treated as a lead to
    review, never as a confirmed high-severity finding — and it can never trip a CI gate, which
    only considers high+ severity.
    """
    severity = severity_for(cwe, confidence)
    return Severity.medium if severity.rank > Severity.medium.rank else severity


def guess_cwe(code: str) -> str:
    for cwe, pattern in _CWE_HINTS:
        if pattern.search(code):
            return cwe
    return "CWE-000"


@dataclass
class ModelPrediction:
    probability: float
    insecure: bool
    cwe: str
    attention: list[AttentionLine] = field(default_factory=list)
    label: str = "LABEL_1"


class CodeBERTDetector:
    """Thin, lazy wrapper around the Hugging Face classifier."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.model_id = self.settings.model_id
        self._tokenizer = None
        self._model = None
        self._torch = None
        self._load_error: str | None = None
        self._loaded = False
        self._id2label = {0: "secure", 1: "insecure"}

    # -- availability ------------------------------------------------------- #
    @property
    def load_error(self) -> str | None:
        return self._load_error

    def available(self) -> bool:
        if self.settings.disable_model:
            self._load_error = "disabled by CODESHIELD_DISABLE_MODEL"
            return False
        return self._ensure_loaded()

    def _ensure_loaded(self) -> bool:
        if self._loaded:
            return self._model is not None
        self._loaded = True
        if self.settings.disable_model:
            self._load_error = "disabled by CODESHIELD_DISABLE_MODEL"
            return False
        try:
            import torch  # noqa: PLC0415
            from transformers import (  # noqa: PLC0415
                AutoModelForSequenceClassification,
                AutoTokenizer,
            )
        except Exception as exc:  # pragma: no cover - depends on optional deps
            self._load_error = f"torch/transformers not installed ({exc.__class__.__name__})"
            return False
        try:  # pragma: no cover - network/weights dependent
            self._torch = torch
            self._tokenizer = AutoTokenizer.from_pretrained(self.model_id)
            self._model = self._load_model(AutoModelForSequenceClassification)
            self._model.eval()
            id2label = getattr(self._model.config, "id2label", None) or {}
            if id2label:
                self._id2label = {int(k): str(v) for k, v in id2label.items()}
            return True
        except Exception as exc:  # pragma: no cover
            self._load_error = f"failed to load {self.model_id} ({exc.__class__.__name__}: {exc})"
            self._model = None
            return False

    def _load_model(self, model_cls):
        """Load the classifier, forcing eager attention so attentions are returned.

        Newer transformers versions default to `sdpa`, which silently returns no attention
        tensors and would leave the line-level heat-map empty (FR-15).
        """
        try:
            return model_cls.from_pretrained(self.model_id, attn_implementation="eager")
        except TypeError:  # older transformers without the kwarg
            return model_cls.from_pretrained(self.model_id)

    @property
    def version(self) -> str:
        return self.model_id

    # -- inference ---------------------------------------------------------- #
    def predict(self, code: str) -> ModelPrediction | None:
        if not self._ensure_loaded():
            return None
        try:  # pragma: no cover - requires model weights
            encoded = self._tokenizer(
                code,
                return_tensors="pt",
                truncation=True,
                padding="max_length",
                max_length=512,
                return_offsets_mapping=True,
                return_attention_mask=True,
            )
            offsets = encoded.pop("offset_mapping")[0].tolist()
            with self._torch.inference_mode():
                output = self._model(**encoded, output_attentions=True)
            probs = output.logits.softmax(dim=-1)[0].tolist()
            insecure_idx = self._insecure_index()
            probability = float(probs[insecure_idx])
            attentions = getattr(output, "attentions", None)
            attention = (
                _attention_to_lines(attentions, code, offsets, self._torch)
                if attentions
                else []
            )
            return ModelPrediction(
                probability=probability,
                insecure=probability >= 0.5,
                cwe=guess_cwe(code),
                attention=attention,
            )
        except Exception:  # pragma: no cover
            return None

    def _insecure_index(self) -> int:
        for idx, label in self._id2label.items():
            if "insecure" in label.lower() or "vulnerab" in label.lower():
                return idx
            if label == "LABEL_1":
                return 1
        return 1


def _attention_to_lines(attentions, code: str, offsets, torch) -> list[AttentionLine]:  # pragma: no cover
    """Attention rollout (PRD §11.2): layers -> tokens -> lines."""
    try:
        stacked = torch.stack([a[0] for a in attentions])          # (layers, heads, seq, seq)
        averaged = stacked.mean(dim=1)                              # (layers, seq, seq)
        identity = torch.eye(averaged.size(-1))
        rollout = identity
        for layer in averaged:
            aug = layer + identity
            aug = aug / aug.sum(dim=-1, keepdim=True)
            rollout = aug @ rollout
        relevance = rollout[0]                                      # CLS row
    except Exception:
        return []

    line_scores: dict[int, float] = {}
    for token_idx, (start, _end) in enumerate(offsets):
        if start == 0 and token_idx == 0:
            continue
        line = code.count("\n", 0, start) + 1
        score = float(relevance[token_idx])
        line_scores[line] = max(line_scores.get(line, 0.0), score)

    if not line_scores:
        return []
    peak = max(line_scores.values()) or 1.0
    return [
        AttentionLine(line=line, score=round(score / peak, 4))
        for line, score in sorted(line_scores.items())
    ]


# --------------------------------------------------------------------------- #
# Ensemble
# --------------------------------------------------------------------------- #


@dataclass
class DetectionOutcome:
    findings: list[Finding]
    notes: list[str]
    model_version: str | None = None
    model_enabled: bool = False


class DetectionService:
    """Runs both engines and merges them into one finding list."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.model = CodeBERTDetector(self.settings)

    def detect(self, analysis: FileAnalysis) -> DetectionOutcome:
        # 1. rule-based baseline
        rule_findings = rules_mod.scan_text(analysis.path, analysis.text, analysis.language)
        findings: list[Finding] = list(rule_findings)
        notes: list[str] = []

        # 2. neural detector (lazy)
        model_enabled = self.model.available()
        model_version = self.model.version if model_enabled else None
        if not model_enabled:
            reason = self.model.load_error or "unavailable"
            notes.append(f"Neural detector inactive: {reason}. Rule-based baseline only.")

        # 3. merge (per function unit)
        units = analysis.functions or [
            FunctionUnit(
                name="<module>",
                start_line=1,
                end_line=max(1, len(analysis.lines)),
                code=analysis.text,
                language=analysis.language,
            )
        ]
        for unit in units:
            if not model_enabled:
                break
            prediction = self.model.predict(unit.code)
            if prediction is None:
                continue
            threshold = self.settings.model_threshold
            if not prediction.insecure or prediction.probability < threshold:
                continue

            overlapping = [
                f
                for f in findings
                if f.file == analysis.path
                and unit.start_line <= f.location.start_line <= unit.end_line
            ]
            if overlapping:
                for f in overlapping:
                    f.engine = Engine.both
                    f.confidence = round(min(0.99, f.confidence + 0.08), 3)
                    f.attention = prediction.attention or f.attention
                    f.syntax_nodes = sorted(set(f.syntax_nodes + ["function_definition"]))
                notes.append(
                    f"Model and rules agree on `{unit.name}` ({prediction.probability:.2f})."
                )
            else:
                cwe = prediction.cwe
                info = cwe_info(cwe)
                confidence = round(prediction.probability, 3)
                findings.append(
                    Finding(
                        file=analysis.path,
                        location=Location(
                            file=analysis.path,
                            start_line=unit.start_line,
                            end_line=unit.end_line,
                            function=unit.name,
                        ),
                        cwe=cwe,
                        cwe_name=info.name,
                        severity=model_only_severity(cwe, confidence),
                        confidence=confidence,
                        engine=Engine.model,
                        title=f"Model flagged `{unit.name}` as potentially insecure (unconfirmed)",
                        rationale=(
                            f"The CodeBERT classifier scored this function "
                            f"{prediction.probability:.2f} on the insecure class, but no rule matched "
                            "it. The classifier alone is not discriminative enough to trust this "
                            "class, so it is reported as an unconfirmed lead and capped at medium "
                            "severity (see scripts/eval_model.py)."
                        ),
                        remediation="Review the function; confirm taint sources before treating it as exploitable.",
                        snippet=snippet_for(analysis.lines, unit.start_line, unit.end_line),
                        syntax_nodes=["function_definition"],
                        attention=prediction.attention,
                        owasp=info.owasp,
                    )
                )

        if model_enabled:
            notes.append(
                f"Neural detector active ({model_version}); "
                f"threshold={self.settings.model_threshold:.2f}."
            )

        return DetectionOutcome(
            findings=findings,
            notes=notes,
            model_version=model_version,
            model_enabled=model_enabled,
        )


def detect_in_text(path: str, text: str, settings: Settings | None = None) -> DetectionOutcome:
    """Convenience helper used by tests and the CLI."""
    return DetectionService(settings).detect(analyze_file(path, text))
