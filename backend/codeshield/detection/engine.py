"""Fusion of deterministic rules and the optional learned detector."""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field

from .. import config
from ..schemas import CodeUnit, Evidence, Finding
from . import model as model_module
from .rules import RuleHit, detect_unit, rule_meta


@dataclass
class BuildResult:
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    model_used: bool = False
    model_id: str = ""


def _fingerprint(path: str, function: str, cwe: str, slug: str, index: int) -> str:
    digest = hashlib.sha256(f"{path}|{function}|{cwe}|{slug}|{index}".encode("utf-8")).hexdigest()
    return digest[:32]


def _hit_to_finding(hit: RuleHit, unit: CodeUnit, index: int) -> Finding:
    meta = hit.meta
    title = meta.get("cwe_title", "Security weakness")
    line = max(unit.start_line, min(hit.line, unit.end_line))
    snippet = hit.snippet or _source_line(unit, line)
    evidence = Evidence(line=line, snippet=snippet, reason=hit.reason, weight=hit.weight)
    return Finding(
        id=uuid.uuid4().hex,
        path=unit.path,
        language=unit.language,
        function=unit.name,
        start_line=unit.start_line,
        end_line=unit.end_line,
        cwe=meta["cwe"],
        cwe_title=title,
        owasp=meta.get("owasp", ""),
        severity=meta.get("severity", "medium"),  # type: ignore[arg-type]
        confidence=round(hit.confidence, 3),
        engine="rules",
        message=hit.message or f"Potential {title.lower()}",
        function_source=unit.source,
        evidence=[evidence],
        knowledge_ref=hit.slug,
        patch_candidates=[],
    )


def _source_line(unit: CodeUnit, line: int) -> str:
    relative = line - unit.start_line
    lines = unit.source.splitlines()
    return lines[relative].strip()[:400] if 0 <= relative < len(lines) else ""


def _model_agreement(base: float, probability: float) -> tuple[float, str]:
    if probability >= config.MODEL_AGREE_THRESHOLD:
        boost = 0.1 * (probability - 0.5)
        return min(0.99, base + boost), "both"
    if probability <= config.MODEL_DISAGREE_THRESHOLD:
        return max(0.05, base * 0.88), "rules"
    return base, "rules"


def _merge(existing: Finding, incoming: Finding) -> None:
    if incoming.confidence > existing.confidence:
        existing.confidence = incoming.confidence
        existing.message = incoming.message
    if incoming.engine == "both" or existing.engine == "both":
        existing.engine = "both"
    known = {(e.line, e.reason) for e in existing.evidence}
    for evidence in incoming.evidence:
        if (evidence.line, evidence.reason) not in known:
            existing.evidence.append(evidence)
    existing.evidence.sort(key=lambda e: -e.weight)


def build_findings(units: list[CodeUnit], enable_model: bool = True) -> BuildResult:
    result = BuildResult()
    model_status = model_module.status()
    use_model = enable_model and model_status.get("available", False)
    if enable_model and not use_model:
        result.notes.append(f"Learned detector unavailable: {model_status.get('reason', 'not loaded')}")
    if use_model:
        result.model_used = True
        result.model_id = str(model_status.get("model_id") or "")
        result.notes.append(
            f"Learned detector: {model_status.get('model_id')} on {model_status.get('device')} "
            f"(agreement >= {config.MODEL_AGREE_THRESHOLD:.2f})"
        )
        if len(units) > 250:
            result.notes.append("Model inference skipped for units beyond the first 250")
    result.notes.append(f"Deterministic rules evaluated {len(units)} code units")

    collected: dict[tuple[str, str, int], Finding] = {}
    counted: dict[tuple[str, str, str, str], int] = {}
    for position, unit in enumerate(units):
        hits = detect_unit(unit)
        if not hits:
            continue
        probability = None
        prediction = None
        if use_model and position < 250:
            prediction = model_module.predict(unit)
            if prediction is not None:
                probability = prediction.probability
        for hit in hits:
            if probability is not None:
                confidence, engine_tag = _model_agreement(hit.confidence, probability)
                hit.confidence = confidence
            else:
                engine_tag = "rules"
            key = (unit.path, hit.meta.get("cwe", ""), hit.line)
            if key in collected:
                incoming = _hit_to_finding(hit, unit, 0)
                incoming.engine = engine_tag
                _merge(collected[key], incoming)
                continue
            counter_key = (unit.path, unit.name, hit.meta.get("cwe", ""), hit.slug)
            counted[counter_key] = counted.get(counter_key, 0) + 1
            finding = _hit_to_finding(hit, unit, counted[counter_key])
            finding.engine = engine_tag
            finding.fingerprint = _fingerprint(
                unit.path, unit.name, finding.cwe, hit.slug, counted[counter_key]
            )
            collected[key] = finding

        if use_model and config.MODEL_ONLY and probability is not None and probability >= config.MODEL_ONLY_THRESHOLD and not hits:
            cwe = "CWE-693"
            title = "Potential security weakness"
            severity = "medium"
            if prediction and prediction.cwe_scores:
                top_label, top_score = next(iter(prediction.cwe_scores.items()))
                if top_score >= 0.5:
                    meta = rule_meta(top_label)
                    cwe, title = meta["cwe"], meta["cwe_title"]
                    severity = meta.get("severity", "medium")
            finding = Finding(
                id=uuid.uuid4().hex, path=unit.path, language=unit.language,
                function=unit.name, start_line=unit.start_line, end_line=unit.end_line,
                cwe=cwe, cwe_title=title, severity=severity, confidence=probability,
                engine="model", message="Learned detector flagged this unit as high risk",
                function_source=unit.source,
                evidence=[Evidence(line=unit.start_line, snippet=_source_line(unit, unit.start_line), reason="Model-only signal", weight=0.5)],
                knowledge_ref="",
            )
            key = (unit.path, cwe, unit.start_line)
            if key not in collected:
                finding.fingerprint = _fingerprint(unit.path, unit.name, cwe, "model", 1)
                collected[key] = finding

    findings = list(collected.values())
    findings.sort(key=lambda f: (-config.SEVERITY_ORDER.get(f.severity, 0), -f.confidence, f.path, f.start_line))
    result.findings = findings
    if findings:
        result.notes.append(f"Deterministic and learned signals produced {len(findings)} candidate findings")
    return result


def catalog() -> list[dict[str, str]]:
    from .rules import _mapping

    entries = []
    for slug, meta in _mapping().items():
        if slug == "__default__":
            continue
        entries.append(
            {
                "slug": slug, "cwe": meta.get("cwe", ""),
                "cwe_title": meta.get("cwe_title", ""), "owasp": meta.get("owasp", ""),
                "severity": meta.get("severity", "medium"),
            }
        )
    return sorted(entries, key=lambda item: item["slug"])
