"""Explain a finding: where it is, why it is risky, and how to fix it.

Attribution for the MVP is evidence-driven (rule hits, dangerous sinks and
taint tokens) rather than raw attention weights; the interface is deliberately
the same shape a gradient/attention method would return, so a stronger
attributor can be dropped in without touching callers.
"""
from __future__ import annotations

import ast
import re
from typing import Optional

from ..knowledge.loader import KnowledgeBase, get_knowledge_base
from ..schemas import CodeUnit, Evidence, Finding

# Concise remediation guidance used to constrain and explain repairs.
REMEDIATION: dict[str, str] = {
    "sql_injection": "Use parameterized queries / prepared statements; never concatenate input into SQL.",
    "rce": "Avoid shell=True and eval/exec; pass argument lists and validate/allow-list input.",
    "insecure_deserialization": "Do not deserialize untrusted data with pickle/marshal; use a safe format such as JSON.",
    "path_traversal_lfi_rfi": "Canonicalize and confine paths; validate against an allow-list and reject '..'.",
    "ssrf": "Resolve and allow-list hosts; block private/link-local ranges and redirects.",
    "xss": "Apply context-aware output encoding; prefer textContent over innerHTML; enable CSP.",
    "open_redirect": "Only redirect to a validated relative path or an allow-listed host.",
    "prototype_pollution": "Allow-list keys and reject __proto__/constructor/prototype before merging.",
    "information_disclosure": "Remove hard-coded secrets and debug flags; load secrets from the environment.",
    "cryptographic_failures": "Replace broken primitives (MD5/SHA1/DES) with SHA-256 or a password KDF.",
    "xxe": "Disable external entity resolution or use defusedxml.",
    "nosql_injection": "Validate request fields and cast to expected scalar types before querying.",
    "ssti": "Never render user input as a template; pass data as context.",
    "race_conditions": "Use atomic operations or locks instead of check-then-use.",
}

_DANGER = re.compile(
    r"execute|query|system|popen|eval|exec|loads?|innerHTML|md5|sha1|secret|password|"
    r"open\(|send_file|redirect|assign|merge|render_template_string",
    re.IGNORECASE,
)
_TAINT = re.compile(
    r"request|req\.|input\(|argv|environ|params|payload|userdata|self\.\w+", re.IGNORECASE
)


class ExplainEngine:
    def __init__(self, kb: Optional[KnowledgeBase] = None) -> None:
        self.kb = kb or get_knowledge_base()

    # -- attribution -------------------------------------------------------
    def attribute(self, unit: CodeUnit, finding: Finding, top_k: int = 5) -> list[Evidence]:
        evidence_by_line = {e.line: e for e in finding.evidence}
        lines = unit.source.splitlines()
        scored: list[Evidence] = []
        for idx, raw in enumerate(lines, start=1):
            abs_line = unit.start_line + idx - 1
            score = 0.0
            reasons: list[str] = []
            if abs_line in evidence_by_line:
                score += 1.0
                reasons.append("rule evidence")
            if _DANGER.search(raw):
                score += 0.6
                reasons.append("dangerous sink")
            if _TAINT.search(raw):
                score += 0.35
                reasons.append("tainted input")
            if score > 0:
                scored.append(
                    Evidence(
                        line=abs_line,
                        snippet=raw.strip()[:200],
                        reason=", ".join(reasons),
                        weight=round(score, 3),
                    )
                )
        scored.sort(key=lambda e: (-e.weight, e.line))
        return scored[:top_k]

    def _ast_nodes(self, unit: CodeUnit, evidence: list[Evidence], top_k: int = 3) -> list[dict]:
        if unit.language != "python":
            return []
        try:
            tree = ast.parse(unit.source)
        except SyntaxError:
            return []
        nodes: list[dict] = []
        for ev in evidence:
            rel = ev.line - unit.start_line + 1
            best = None
            for node in ast.walk(tree):
                start = getattr(node, "lineno", None)
                end = getattr(node, "end_lineno", None)
                if start is None or end is None:
                    continue
                if start <= rel <= end:
                    span = end - start
                    if best is None or span < best[1]:
                        best = (node, span)
            if best is not None:
                nodes.append(
                    {
                        "line": ev.line,
                        "node_type": type(best[0]).__name__,
                        "col": getattr(best[0], "col_offset", 0),
                    }
                )
            if len(nodes) >= top_k:
                break
        return nodes

    # -- public ------------------------------------------------------------
    def explain(self, finding: Finding, unit: CodeUnit) -> dict:
        evidence = self.attribute(unit, finding)
        if not finding.evidence:
            finding.evidence = evidence
        item = self.kb.for_slug(finding.knowledge_ref) if finding.knowledge_ref else None
        why = item.description if item else (
            "No specific knowledge module matched; the classifier flagged the function as insecure."
        )
        remediation = (
            REMEDIATION.get(finding.knowledge_ref or "", "")
            or "Review the flagged lines and apply the framework's built-in defence."
        )
        summary = (
            f"{finding.cwe_title or finding.cwe} ({finding.cwe}): {finding.message} "
            f"Severity {finding.severity.upper()} (confidence {finding.confidence:.0%}), "
            f"engine={finding.engine}."
        )
        return {
            "summary": summary,
            "why": why,
            "remediation": remediation,
            "cwe": finding.cwe,
            "cwe_title": finding.cwe_title,
            "owasp": finding.owasp,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "engine": finding.engine,
            "knowledge_ref": finding.knowledge_ref,
            "knowledge_name": item.name if item else None,
            "evidence": [e.model_dump() for e in evidence],
            "ast_nodes": self._ast_nodes(unit, evidence),
            "attribution_method": "heuristic-evidence",
        }
