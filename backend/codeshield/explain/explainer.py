"""Knowledge-grounded explanations, evidence attribution, and AST citations."""
from __future__ import annotations

import ast
import json
import re
from functools import lru_cache
from typing import Any, Optional

from .. import config
from ..detection import model as model_module
from ..knowledge.loader import get_knowledge_base
from ..schemas import AstNode, CodeUnit, Finding

_DANGER_TERMS = {
    "eval": 1.0, "exec": 1.0, "os.system": 1.0, "subprocess": 0.8, "shell=true": 0.95,
    "pickle": 0.9, "yaml.load": 0.8, "execute": 0.7, "executemany": 0.7, "query(": 0.7,
    "innerhtml": 0.9, "outerhtml": 0.9, "dangerouslysetinnerhtml": 0.95, "document.write": 0.85,
    "open(": 0.5, "send_file": 0.7, "requests.": 0.6, "httpx.": 0.6, "fetch(": 0.6,
    "redirect(": 0.7, "password": 0.6, "secret": 0.7, "api_key": 0.8, "verify=false": 0.9,
    "md5": 0.5, "sha1": 0.5, "deserialize": 0.9, "readobject": 0.9, "createhash": 0.5,
    "render_template_string": 0.95, "fromstring": 0.7, "xml": 0.4,
}
_SOURCE_TERMS = ("request.", "req.", "input(", "argv", "filename", "userinput", "params", "body")


@lru_cache(maxsize=1)
def _remediations() -> dict[str, dict[str, Any]]:
    path = config.KNOWLEDGE_DIR / "remediations.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _kb_excerpt(slug: str) -> str:
    item = get_knowledge_base().get(slug)
    if not item or not item.description:
        return ""
    return item.description[:900]


def _kb_remediation_section(slug: str) -> list[str]:
    if not re.fullmatch(r"[a-z0-9_]{1,80}", slug or ""):
        return []
    path = config.VULN_KB_DIR / f"{slug}.md"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    match = re.search(r"^## (?:Remediation|Prevention|Mitigation|Defense)\s*$", text, re.MULTILINE | re.IGNORECASE)
    if not match:
        return []
    section = text[match.end():]
    next_heading = re.search(r"^##\s", section, re.MULTILINE)
    if next_heading:
        section = section[:next_heading.start()]
    bullets = []
    for line in section.splitlines():
        cleaned = line.strip().lstrip("-*").strip()
        if len(cleaned) > 15:
            bullets.append(cleaned)
    return bullets[:5]


def _lexical_weights(unit: CodeUnit, evidence_lines: set[int]) -> dict[int, float]:
    weights: dict[int, float] = {line: 1.0 for line in evidence_lines}
    for index, line in enumerate(unit.source.splitlines()):
        line_no = unit.start_line + index
        lowered = line.lower()
        score = 0.0
        for term, value in _DANGER_TERMS.items():
            if term in lowered:
                score += value
        for term in _SOURCE_TERMS:
            if term in lowered:
                score += 0.35
        if score and line_no not in weights:
            weights[line_no] = score
    if not weights:
        weights[unit.start_line] = 1.0
    maximum = max(weights.values()) or 1.0
    return {line: value / maximum for line, value in weights.items()}


def _attention_weights(unit: CodeUnit, evidence_lines: set[int]) -> tuple[Optional[dict[int, float]], Optional[dict[str, Any]]]:
    analysis = model_module.analyze(unit)
    if analysis is None or not analysis.tokens:
        return None, None
    weights: dict[int, float] = {}
    for token in analysis.tokens:
        line = unit.start_line + token.line - 1
        if token.weight > weights.get(line, 0.0):
            weights[line] = token.weight
    for line in evidence_lines:
        weights[line] = min(1.0, weights.get(line, 0.0) + 0.6)
    maximum = max(weights.values()) or 1.0
    weights = {line: value / maximum for line, value in weights.items()}
    top_lines = sorted(weights, key=lambda line: -weights[line])[:5]
    agreement = len(set(top_lines) & evidence_lines) / max(1, len(set(top_lines) | evidence_lines))
    metadata = {
        "method": analysis.method,
        "probability": analysis.probability,
        "agreement": round(agreement, 2),
        "cwe_scores": analysis.cwe_scores,
    }
    return weights, metadata


def _python_nodes(unit: CodeUnit, evidence_lines: set[int]) -> list[AstNode]:
    try:
        tree = ast.parse(unit.source)
    except SyntaxError:
        return _lexical_nodes(unit, evidence_lines)
    nodes: list[AstNode] = []
    sources = unit.source.splitlines()
    for node in ast.walk(tree):
        line = getattr(node, "lineno", None)
        if line is None:
            continue
        absolute = line + unit.start_line - 1
        if absolute not in evidence_lines and not any(abs(absolute - target) <= 1 for target in evidence_lines):
            continue
        node_type = type(node).__name__
        role = "context"
        snippet = ""
        try:
            snippet = (ast.get_source_segment(unit.source, node) or "")[:240]
        except Exception:
            snippet = sources[line - 1][:240] if 0 <= line - 1 < len(sources) else ""
        lowered = snippet.lower()
        if any(term in lowered for term in ("eval", "exec", "execute", "system", "pickle", "innerhtml", "open(", "fetch(", "redirect")):
            role = "sink"
        if any(term in lowered for term in ("request", "req.", "input(", "argv", "filename")):
            role = "source"
        if node_type in {"Call", "Assign", "Attribute", "Subscript", "BinOp", "JoinedStr", "Dict", "Constant"}:
            nodes.append(
                AstNode(
                    line=absolute, node_type=node_type, col=getattr(node, "col_offset", 0),
                    snippet=snippet, role=role,
                )
            )
    return _dedupe_nodes(nodes)[:28]


def _lexical_nodes(unit: CodeUnit, evidence_lines: set[int]) -> list[AstNode]:
    nodes: list[AstNode] = []
    lines = unit.source.splitlines()
    for index, line in enumerate(lines):
        absolute = unit.start_line + index
        if absolute not in evidence_lines and not any(abs(absolute - target) <= 1 for target in evidence_lines):
            continue
        match = re.search(r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(", line)
        if match:
            role = "source" if any(term in line.lower() for term in _SOURCE_TERMS) else "sink"
            nodes.append(
                AstNode(line=absolute, node_type="call", col=match.start(), snippet=line.strip()[:240], role=role)
            )
        elif "=" in line:
            nodes.append(AstNode(line=absolute, node_type="assignment", snippet=line.strip()[:240], role="context"))
    return _dedupe_nodes(nodes)[:24]


def _treesitter_nodes(unit: CodeUnit, evidence_lines: set[int]) -> list[AstNode]:
    try:
        from tree_sitter_language_pack import get_parser
        parser = get_parser("tsx" if unit.language == "tsx" else unit.language)
    except Exception:
        return _lexical_nodes(unit, evidence_lines)
    try:
        tree = parser.parse(unit.source.encode("utf-8"))
    except Exception:
        return _lexical_nodes(unit, evidence_lines)
    nodes: list[AstNode] = []
    interesting = {
        "call_expression", "method_invocation", "assignment_expression", "assignment",
        "binary_expression", "member_expression", "field_access", "object_creation_expression",
        "template_string", "string_literal", "variable_declarator", "local_variable_declaration",
    }

    def visit(node) -> None:
        line = node.start_point[0] + unit.start_line
        if line in evidence_lines or any(abs(line - target) <= 1 for target in evidence_lines):
            if node.type in interesting:
                snippet = unit.source.encode("utf-8")[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
                lowered = snippet.lower()
                role = "context"
                if any(term in lowered for term in ("eval", "exec", "query", "system", "innerhtml", "open", "readfile", "fetch", "redirect")):
                    role = "sink"
                if any(term in lowered for term in ("req.", "request", "location", "process.argv")):
                    role = "source"
                nodes.append(
                    AstNode(line=line, node_type=node.type, col=node.start_point[1],
                            snippet=snippet.strip()[:240], role=role)
                )
        for child in node.children:
            visit(child)

    visit(tree.root_node)
    return _dedupe_nodes(nodes)[:28]


def _dedupe_nodes(nodes: list[AstNode]) -> list[AstNode]:
    seen: set[tuple[int, str, str]] = set()
    output = []
    for node in sorted(nodes, key=lambda n: (n.line, n.col)):
        key = (node.line, node.node_type, node.snippet)
        if key in seen:
            continue
        seen.add(key)
        output.append(node)
    return output


def explain_finding(finding: Finding, unit: Optional[CodeUnit], enable_model: bool = True) -> dict[str, Any]:
    slug = finding.knowledge_ref or ""
    kb = get_knowledge_base().get(slug) if slug else None
    remediation_data = _remediations().get(slug, {})
    evidence_lines = {item.line for item in finding.evidence}
    method = "rules"
    model_meta: Optional[dict[str, Any]] = None
    weights: dict[int, float]
    if unit is not None:
        attention, model_meta = _attention_weights(unit, evidence_lines) if enable_model else (None, None)
        if attention and model_meta and model_meta.get("method") == "attention-rollout":
            weights = attention
            method = "attention-rollout"
        else:
            weights = _lexical_weights(unit, evidence_lines)
        finding.ast_nodes = (
            _python_nodes(unit, evidence_lines) if unit.language == "python"
            else _treesitter_nodes(unit, evidence_lines)
        )
    else:
        weights = {line: 1.0 for line in evidence_lines}
        finding.ast_nodes = []

    remediation = remediation_data.get("remediation") or _kb_remediation_section(slug) or [
        "Validate untrusted input at the boundary and apply the security control described in the linked guidance.",
        "Add a regression test that reproduces the issue and fails without the fix.",
    ]
    references = remediation_data.get("references") or []
    if kb and kb.cwe:
        references = references or [f"https://cwe.mitre.org/data/definitions/{kb.cwe.split('-')[-1]}.html"]
    excerpt = _kb_excerpt(slug)
    summary = (
        f"{finding.cwe_title or kb.cwe_title if kb else finding.cwe_title} in "
        f"{finding.function} at {finding.path}:{finding.evidence[0].line if finding.evidence else finding.start_line}."
    )
    explanation = {
        "summary": summary,
        "why": excerpt or (finding.evidence[0].reason if finding.evidence else "") or finding.message,
        "attack": remediation_data.get("attack", "The data path shown in the evidence reaches a dangerous operation without an effective control."),
        "remediation": remediation,
        "references": references,
        "evidence": [item.model_dump() for item in finding.evidence],
        "attribution": {
            "method": method,
            "lines": [
                {"line": line, "weight": round(weight, 3)}
                for line, weight in sorted(weights.items(), key=lambda item: -item[1])[:24]
            ],
            "model": model_meta,
        },
        "knowledge": {
            "slug": slug,
            "name": kb.name if kb else finding.cwe_title,
            "cwe": finding.cwe,
            "owasp": finding.owasp or (kb.owasp if kb else ""),
            "severity": finding.severity,
            "description": excerpt,
        },
        "generator": "knowledge-grounded",
    }
    return explanation
