"""Stage 4 — explainability (PRD §7.4, §11.2).

Turns a raw detection into an explanation a developer can act on:

* aggregate attribution to **lines** (from model attention when available, otherwise a
  transparent taint-based salience),
* attribute the likely root cause to **syntax nodes** (FR-16),
* compute a second attribution and report **agreement** (FR-17) so a single method is never
  presented as ground truth,
* write the short natural-language rationale (FR-18).
"""

from __future__ import annotations

import re

from ..models import AttentionLine, Engine, Finding
from .parsing import FileAnalysis
from .severity import cwe_info

# Tokens that commonly mark a taint source or a sink — used for the transparent salience.
_TAINT_WORDS = re.compile(
    r"\b(?:request|req\.|input|argv|params|body|query|user|cookie|header|env|getParameter|"
    r"system|popen|exec|eval|execute|query|loads?|innerHTML|write|open|urlopen|fetch)\b",
    re.IGNORECASE,
)
_CONCAT = re.compile(r"(\+|\+|%|\bf['\"]|\.format\s*\()")
_NODE_HINTS: list[tuple[str, re.Pattern]] = [
    ("call_expression", re.compile(r"\w+\s*\([^)]*\)")),
    ("binary_expression", re.compile(r"\S\s*(\+|%|\|\|)\s*\S")),
    ("string_literal", re.compile(r"['\"][^'\"]*['\"]")),
    ("member_access", re.compile(r"\w+\.\w+")),
    ("assignment", re.compile(r"\s=\s")),
    ("f_string", re.compile(r"\bf['\"]")),
    ("argument", re.compile(r"\(\s*\w")),
]


def salience_lines(analysis: FileAnalysis, start_line: int, end_line: int, span: int = 4) -> list[AttentionLine]:
    """A transparent, dependency-free attribution over nearby lines.

    Every line in a window around the finding is scored by proximity + taint vocabulary +
    concatenation operators. This is deliberately simple and is *labelled as a heuristic*
    wherever it is shown, so it is never confused with model attention.
    """
    lo = max(1, start_line - span)
    hi = min(len(analysis.lines), end_line + span)
    scores: dict[int, float] = {}
    for n in range(lo, hi + 1):
        text = analysis.lines[n - 1]
        score = 0.05
        score += 0.5 if start_line <= n <= end_line else 0.0
        score += 0.25 * len(_TAINT_WORDS.findall(text))
        score += 0.2 * len(_CONCAT.findall(text))
        score += 0.3 if "=" in text else 0.0
        scores[n] = round(score, 4)
    peak = max(scores.values()) or 1.0
    return [
        AttentionLine(line=line, score=round(score / peak, 4))
        for line, score in sorted(scores.items())
    ]


def syntax_nodes_for(analysis: FileAnalysis, finding: Finding) -> list[str]:
    """Return likely syntax-node kinds for the flagged region (FR-16)."""
    kinds: set[str] = set(finding.syntax_nodes)
    lo = max(1, finding.location.start_line)
    hi = min(len(analysis.lines), finding.location.end_line)
    region = "\n".join(analysis.lines[lo - 1 : hi])
    for name, pattern in _NODE_HINTS:
        if pattern.search(region):
            kinds.add(name)
    # Python's real AST lets us name nodes precisely.
    if analysis.language == "python":
        kinds |= _python_node_kinds(region)
    return sorted(kinds)


def _python_node_kinds(region: str) -> set[str]:
    import ast

    kinds: set[str] = set()
    try:
        tree = ast.parse(region)
    except SyntaxError:
        return kinds
    for node in ast.walk(tree):
        kinds.add(type(node).__name__)
    return kinds


def _top_lines(attention: list[AttentionLine], k: int) -> list[int]:
    ranked = sorted(attention, key=lambda a: -a.score)[:k]
    return [a.line for a in ranked if a.score > 0]


def second_opinion(analysis: FileAnalysis, finding: Finding) -> tuple[list[int], float]:
    """Recompute attribution with the salience method and measure agreement (FR-17).

    Returns ``(salience_top_lines, agreement)`` where agreement is the Jaccard overlap of the
    model's top-5 lines and the salience top-5 lines.
    """
    sal = salience_lines(analysis, finding.location.start_line, finding.location.end_line)
    sal_top = set(_top_lines(sal, 5))
    model_top = set(_top_lines(finding.attention, 5)) if finding.attention else set()
    if not model_top or not sal_top:
        return sorted(sal_top), 0.0
    union = model_top | sal_top
    agreement = len(model_top & sal_top) / len(union) if union else 0.0
    return sorted(sal_top), round(agreement, 3)


def build_rationale(analysis: FileAnalysis, finding: Finding, agreement: float) -> str:
    info = cwe_info(finding.cwe)
    source = {
        Engine.model: "the CodeBERT classifier",
        Engine.rules: "the rule-based baseline",
        Engine.both: "the CodeBERT classifier and the rules",
    }[finding.engine]
    top = _top_lines(finding.attention, 3)
    where = ", ".join(f"line {n}" for n in top) if top else f"line {finding.location.start_line}"
    if finding.engine is Engine.rules:
        agreement_note = ""
    elif agreement >= 0.4:
        agreement_note = " The two attribution methods agree on the hot lines."
    else:
        agreement_note = (
            " The two attribution methods agree only partially — treat the highlight as a "
            "likely, not certain, cause."
        )
    return (
        f"{info.name} ({info.cwe}, {info.owasp}). Reported by {source} with "
        f"{finding.confidence:.0%} confidence. The most relevant code is at {where}."
        f"{agreement_note}"
    )


def _merge_attention(
    attention: list[AttentionLine], salience: list[AttentionLine]
) -> list[AttentionLine]:
    merged = {row.line: row.score for row in salience}
    for row in attention:
        merged[row.line] = max(merged.get(row.line, 0.0), row.score)
    return [AttentionLine(line=line, score=score) for line, score in sorted(merged.items())]


def enrich(finding: Finding, analysis: FileAnalysis) -> Finding:
    """Fill in the explanation fields for one finding, in place, and return it."""
    salience = salience_lines(analysis, finding.location.start_line, finding.location.end_line)
    if not finding.attention:
        finding.attention = salience
    elif len(finding.attention) < 2:
        # A rule matched one line; widen the heat-map with the surrounding context.
        finding.attention = _merge_attention(finding.attention, salience)
    finding.syntax_nodes = syntax_nodes_for(analysis, finding)
    _sal_top, agreement = second_opinion(analysis, finding)
    finding.rationale = build_rationale(analysis, finding, agreement)
    if finding.exploit is None:
        finding.exploit = _default_exploit(finding.cwe)
    if finding.remediation is None:
        finding.remediation = _default_remediation(finding.cwe)
    return finding


def _default_exploit(cwe: str) -> str | None:
    return {
        "CWE-89": "An attacker reshapes the query (e.g. `' OR 1=1 --`) to bypass filters.",
        "CWE-78": "Shell metacharacters in the input (`;`, `&&`, `|`) run extra commands.",
        "CWE-79": "Injected markup executes in the victim's browser and can steal sessions.",
        "CWE-95": "Supplied input is executed as code, giving arbitrary code execution.",
        "CWE-502": "A crafted payload executes code during deserialization.",
        "CWE-22": "`../` sequences escape the intended directory and read foreign files.",
        "CWE-918": "A user-supplied URL reaches internal services or cloud metadata.",
        "CWE-798": "A committed credential grants access to whoever can read the repository.",
        "CWE-328": "Hash collisions let an attacker forge data with the same digest.",
        "CWE-330": "Predictable tokens can be guessed to hijack a session.",
    }.get(cwe)


def _default_remediation(cwe: str) -> str | None:
    return {
        "CWE-89": "Use parameterised queries / prepared statements.",
        "CWE-78": "Avoid the shell; pass an argument list with shell disabled.",
        "CWE-79": "Escape on output or sanitise HTML with a vetted library.",
        "CWE-95": "Replace dynamic evaluation with safe parsing or a dispatch table.",
        "CWE-502": "Deserialise with a safe format (JSON) or a restricted loader.",
        "CWE-22": "Canonicalise the path and confine it to an allow-listed base directory.",
        "CWE-918": "Validate destinations against an allow-list and block internal ranges.",
        "CWE-798": "Move secrets to environment/secret storage and rotate the exposed value.",
        "CWE-328": "Use SHA-256+ (or bcrypt/argon2 for passwords).",
        "CWE-330": "Use a CSPRNG (secrets / crypto.randomBytes / SecureRandom).",
    }.get(cwe)


def explain_all(findings: list[Finding], analysis: FileAnalysis) -> list[Finding]:
    return [enrich(f, analysis) for f in findings]
