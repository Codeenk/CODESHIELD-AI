"""Stage 5b — patch verification (PRD §7.5 FR-21..FR-23, §9).

Every candidate patch passes through explicit checks before it can be shown as safe:

* **parses** — the patched file still parses (hard requirement),
* **signature preserved** — public function signatures are unchanged where detectable,
* **re-scan clean** — the original weakness no longer fires in the patched region and no new
  weakness was introduced there (FR-21),
* **tests** — the project's unit tests run *in the sandbox only* (FR-22); skipped when no
  sandbox is configured, and said so plainly.

The resulting ``PatchStatus`` is ``verified`` / ``partial`` / ``unverified`` — the UI must never
present the last two as safe (FR-23).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from ..config import Settings, get_settings
from ..models import Finding, Patch, PatchStatus
from . import rules as rules_mod
from .parsing import FileAnalysis, analyze_file
from .repair import Candidate


@dataclass
class VerificationOutcome:
    status: PatchStatus
    checks: list[str]
    residual: int = 0
    regressions: int = 0


def _function_signatures(text: str, language: str) -> dict[str, tuple]:
    if language != "python":
        return {}
    signatures: dict[str, tuple] = {}
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return signatures
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            signatures[node.name] = tuple(a.arg for a in node.args.args)
    return signatures


def verify_candidate(
    candidate: Candidate,
    finding: Finding,
    analysis: FileAnalysis,
    settings: Settings | None = None,
    run_tests: bool = False,
) -> VerificationOutcome:
    settings = settings or get_settings()
    patch = candidate.patch
    checks: list[str] = []

    # 1. parse check ------------------------------------------------------- #
    patched_analysis = analyze_file(analysis.path, candidate.patched_text, analysis.language)
    if patched_analysis.parse_error:
        checks.append(f"parse: FAILED ({patched_analysis.parse_error})")
        return VerificationOutcome(PatchStatus.unverified, checks)
    checks.append("parse: OK")

    # 2. signature preservation -------------------------------------------- #
    before = _function_signatures(analysis.text, analysis.language)
    after = _function_signatures(candidate.patched_text, analysis.language)
    changed = [name for name in before if name in after and before[name] != after[name]]
    checks.append(
        f"signatures: CHANGED {', '.join(sorted(changed))}" if changed else "signatures: preserved"
    )

    # 3. re-scan ------------------------------------------------------------ #
    start = finding.location.start_line
    end = start + max(0, len(patch.patched_code.splitlines()) - 1)
    rescan = rules_mod.scan_text(analysis.path, candidate.patched_text, analysis.language)
    region = [f for f in rescan if f.location.start_line <= end and f.location.end_line >= start]
    residual = sum(1 for f in region if f.cwe == finding.cwe)
    regressions = sum(1 for f in region if f.cwe != finding.cwe)
    checks.append(f"re-scan: {residual} residual, {regressions} new in region")

    # 4. tests (sandbox only) ---------------------------------------------- #
    if run_tests:
        checks.append("tests: requested but no sandbox runner wired up — not executed")
    else:
        checks.append("tests: not run (no sandbox configured)")

    if residual or regressions or changed:
        status = PatchStatus.partial
    else:
        status = PatchStatus.verified

    return VerificationOutcome(status, checks, residual, regressions)


def verify_and_finalize(
    candidate: Candidate,
    finding: Finding,
    analysis: FileAnalysis,
    settings: Settings | None = None,
    run_tests: bool = False,
) -> Patch:
    outcome = verify_candidate(candidate, finding, analysis, settings, run_tests)
    patch = candidate.patch
    patch.status = outcome.status
    patch.verification = outcome.checks
    return patch
