"""Fuse rule-based detections with the model's signal into findings."""
from __future__ import annotations

import hashlib
import uuid
from typing import Optional

from .. import config
from ..knowledge.loader import KnowledgeBase, get_knowledge_base
from ..schemas import CodeUnit, Finding
from .model import _BaseDetector, build_detector
from .rules import Detection, RuleEngine

MODEL_AGREE_THRESHOLD = 0.50
MODEL_ONLY_SLUG = "generic_insecure"


def fingerprint(path: str, function: str, cwe: str, lines: list[int]) -> str:
    key = f"{path}|{function}|{cwe}|{sorted(lines)}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


class DetectionEngine:
    def __init__(
        self,
        kb: Optional[KnowledgeBase] = None,
        rules: Optional[RuleEngine] = None,
        detector: Optional[_BaseDetector] = None,
    ) -> None:
        self.kb = kb or get_knowledge_base()
        self.rules = rules or RuleEngine()
        self.detector = detector if detector is not None else build_detector()

    # -- helpers -----------------------------------------------------------
    def _severity_for(self, slug: str, override: Optional[str]) -> str:
        if override:
            return override
        item = self.kb.for_slug(slug)
        return item.severity or "medium"

    def _build_rule_finding(
        self, unit: CodeUnit, det: Detection, model_prob: Optional[float]
    ) -> Finding:
        engine = "rules"
        confidence = det.base_confidence
        if model_prob is not None:
            if model_prob >= MODEL_AGREE_THRESHOLD:
                confidence = det.base_confidence + 0.15
                engine = "both"
            else:
                confidence -= 0.10
        info = self.kb.for_slug(det.slug)
        lines = [e.line for e in det.evidence]
        return Finding(
            id=uuid.uuid4().hex[:12],
            path=unit.path,
            language=unit.language,
            function=unit.name,
            start_line=unit.start_line,
            end_line=unit.end_line,
            cwe=det.cwe,
            cwe_title=info.cwe_title or "",
            owasp=info.owasp or "",
            severity=self._severity_for(det.slug, det.severity_override),
            confidence=confidence,
            engine=engine,
            message=det.message,
            function_source=unit.source,
            evidence=det.evidence,
            knowledge_ref=det.slug if self.kb.get(det.slug) else None,
            fingerprint=fingerprint(unit.path, unit.name, det.cwe, lines),
        )

    def _build_model_finding(self, unit: CodeUnit, prob: float) -> Finding:
        info = self.kb.for_slug(MODEL_ONLY_SLUG)
        return Finding(
            id=uuid.uuid4().hex[:12],
            path=unit.path,
            language=unit.language,
            function=unit.name,
            start_line=unit.start_line,
            end_line=unit.end_line,
            cwe=info.cwe or "CWE-693",
            cwe_title=info.cwe_title or "Protection Mechanism Failure",
            owasp=info.owasp or "",
            severity="medium",
            confidence=max(0.5, min(prob, 0.9)),
            engine="model",
            message=(
                "The CodeBERT classifier flagged this function as insecure, but no "
                "rule matched a specific flaw class. Treat as low-confidence."
            ),
            function_source=unit.source,
            evidence=[],
            knowledge_ref=None,
            fingerprint=fingerprint(unit.path, unit.name, info.cwe or "CWE-693", []),
        )

    # -- public ------------------------------------------------------------
    def detect_unit(self, unit: CodeUnit) -> list[Finding]:
        detections = self.rules.scan(unit)
        model_prob: Optional[float] = None
        if self.detector.enabled:
            probs = self.detector.predict_proba([unit.source])
            model_prob = probs[0] if probs else None

        findings = [self._build_rule_finding(unit, det, model_prob) for det in detections]
        # The reference model is indiscriminate, so a standalone model-only
        # finding is opt-in and needs a very high score to avoid false positives.
        if (
            not findings
            and config.MODEL_ONLY
            and model_prob is not None
            and model_prob >= config.MODEL_ONLY_THRESHOLD
        ):
            findings.append(self._build_model_finding(unit, model_prob))
        return findings
