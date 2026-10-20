"""Static and dynamic verification for repair candidates."""
from __future__ import annotations

import ast
import re
from typing import Optional

from .. import config
from ..detection.rules import RuleHit, detect_unit, rule_meta
from ..schemas import CodeUnit, Finding, PatchCandidate
from ..repair.templates import TemplateFix, unified_diff
from .runner import TestRunner


def _patched_unit(unit: CodeUnit, source: str) -> CodeUnit:
    return CodeUnit(
        path=unit.path, language=unit.language, name=unit.name,
        start_line=unit.start_line,
        end_line=unit.start_line + max(0, len(source.splitlines()) - 1),
        source=source, container=unit.container, signature=unit.signature, kind=unit.kind,
    )


def _python_signature(source: str) -> Optional[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
            return f"{prefix} {node.name}({ast.unparse(node.args)})"
    return None


def _generic_signature(source: str, language: str) -> Optional[str]:
    patterns = [
        re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(([^)]*)\)", re.M),
        re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>", re.M),
        re.compile(r"^\s*(?:[A-Za-z_$][\w$]*\s*\(([^)]*)\)\s*\{)", re.M),
        re.compile(r"^\s*(?:public|private|protected|static|final|synchronized|\s)+[\w<>\[\],.?]+\s+([A-Za-z_$][\w$]*)\s*\(([^;{]*)\)", re.M),
    ]
    for pattern in patterns:
        match = pattern.search(source)
        if not match:
            continue
        groups = [group for group in match.groups() if group is not None]
        params = groups[-1] if groups else ""
        names = re.findall(r"[A-Za-z_$][\w$]*", params)
        return "|".join(sorted(names))
    return None


def _same_signature(original: CodeUnit, patched: str) -> bool:
    if original.kind in {"module", "file"} or original.name == "<module>":
        return True
    if original.language == "python":
        before = _python_signature(original.source)
        after = _python_signature(patched)
        return bool(before and after and before == after)
    before = _generic_signature(original.source, original.language)
    after = _generic_signature(patched, original.language)
    return bool(before and after and before == after)


def _checks(
    finding: Finding, unit: CodeUnit, patched: str, hits: list[RuleHit],
    original_slugs: set[str], tests: Optional[dict],
) -> list[dict]:
    checks = [
        {
            "name": "Parses cleanly",
            "passed": _parses(patched, unit.language),
            "detail": "Patched unit parses in the target language.",
        }
    ]
    persists = [hit for hit in hits if hit.slug == (finding.knowledge_ref or "") or hit.meta["cwe"] == finding.cwe]
    checks.append(
        {
            "name": "Original weakness removed",
            "passed": not persists,
            "detail": "No rule still reports the original CWE in the patched unit."
            if not persists else f"Still detected: {', '.join(sorted({h.slug for h in persists}))}",
        }
    )
    new_high = [
        hit for hit in hits
        if hit.slug not in original_slugs and rule_meta(hit.slug).get("severity") in {"critical", "high"}
    ]
    checks.append(
        {
            "name": "No new high or critical findings",
            "passed": not new_high,
            "detail": "No new high/critical rule fired." if not new_high
            else f"New risk: {', '.join(sorted({h.slug for h in new_high}))}",
        }
    )
    checks.append(
        {
            "name": "Public signature preserved",
            "passed": _same_signature(unit, patched),
            "detail": "Function name and parameters are unchanged.",
        }
    )
    if tests is None:
        checks.append({"name": "Existing tests", "passed": None, "detail": "No test project is available."})
    else:
        checks.append(tests)
    return checks


def _parses(source: str, language: str) -> bool:
    if language == "python":
        try:
            ast.parse(source)
            return True
        except SyntaxError:
            return False
    return bool(source.strip()) and source.count("{") <= source.count("}") + 1


def verify_candidate(
    finding: Finding, unit: CodeUnit, fix: TemplateFix,
    original_hits: Optional[list[RuleHit]] = None,
    runner: Optional[TestRunner] = None,
) -> PatchCandidate:
    patched_unit = _patched_unit(unit, fix.source)
    hits = detect_unit(patched_unit)
    original_slugs = {hit.slug for hit in (original_hits or [])}
    original_slugs.add(finding.knowledge_ref or "")

    tests: Optional[dict] = None
    tests_inconclusive = False
    if runner is not None and runner.has_tests:
        if not runner.enabled:
            tests = {
                "name": "Existing tests", "passed": None,
                "detail": "Tests exist but execution is disabled (CODESHIELD_RUN_TESTS=false).",
            }
            tests_inconclusive = True
        else:
            outcome = runner.run(unit.path, fix.source)
            tests = {
                "name": "Existing tests", "passed": outcome.status == "passed",
                "detail": f"{outcome.status}: {outcome.detail}"[:1200],
            }
            if outcome.status != "passed":
                tests["passed"] = False if outcome.status == "failed" else None
                tests_inconclusive = outcome.status != "failed"
    elif runner is not None:
        tests = {"name": "Existing tests", "passed": None, "detail": "No tests found in the project."}

    checks = _checks(finding, unit, fix.source, hits, original_slugs, tests)
    parse_ok = checks[0]["passed"]
    persists = not checks[1]["passed"]
    new_high = not checks[2]["passed"]
    signature_ok = checks[3]["passed"]
    test_failed = bool(tests and tests["passed"] is False)

    if not parse_ok or persists or new_high or not signature_ok or test_failed:
        status = "unverified"
    elif fix.semantic_risk or tests_inconclusive:
        status = "partially_verified"
    else:
        status = "verified"

    return PatchCandidate(
        source=fix.source,
        summary=fix.summary,
        unified_diff=unified_diff(unit.source, fix.source, unit.path),
        verification=status,
        checks=checks,
        rationale=fix.rationale,
        semantic_risk=fix.semantic_risk,
        generator=fix.generator,
        language=unit.language,
    )


def rank(candidates: list[PatchCandidate]) -> list[PatchCandidate]:
    order = {"verified": 0, "partially_verified": 1, "unverified": 2}
    candidates.sort(
        key=lambda c: (
            order.get(c.verification, 3), c.semantic_risk,
            0 if c.generator == "template" else 1,
        )
    )
    for index, candidate in enumerate(candidates, start=1):
        candidate.rank = index
    return candidates
