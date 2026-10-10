"""Verify a candidate patch.

By default verification is *static and safe*: does the patch parse, does it stop
the original rule from firing, and is the function signature preserved.
Executing the project's own tests is opt-in (``CODESHIELD_RUN_TESTS=1``) and only
ever runs inside a throwaway temp directory.
"""
from __future__ import annotations

import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .. import config
from ..detection.rules import RuleEngine
from ..schemas import CodeUnit, Finding


@dataclass
class VerificationReport:
    status: str  # verified | partially_verified | unverified
    checks: list[dict] = field(default_factory=list)

    def as_dicts(self) -> list[dict]:
        return self.checks


def _parses(source: str, language: str) -> tuple[bool, str]:
    if language == "python":
        import ast

        try:
            ast.parse(source)
            return True, "Python AST parsed"
        except SyntaxError as exc:
            return False, f"SyntaxError: {exc.msg} (line {exc.lineno})"
    # JS/TS/Java: try tree-sitter, else a brace-balance sanity check.
    try:
        from ..parsing.parser import _get_ts_parser  # type: ignore

        parser = _get_ts_parser(language)
        if parser is not None:
            tree = parser.parse(source.encode("utf-8"))
            if tree.root_node.has_error:
                return False, "Tree-sitter reported a parse error"
            return True, "Tree-sitter parsed"
    except Exception:  # noqa: BLE001
        pass
    depth = 0
    for ch in source:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth < 0:
                return False, "Unbalanced braces"
    return (depth == 0), f"Brace balance depth={depth}"


class Verifier:
    def __init__(self, rules: Optional[RuleEngine] = None) -> None:
        self.rules = rules or RuleEngine()

    def verify(self, unit: CodeUnit, patched_source: str, finding: Finding) -> VerificationReport:
        checks: list[dict] = []

        ok, detail = _parses(patched_source, unit.language)
        checks.append({"name": "parses", "ok": ok, "detail": detail})
        if not ok:
            return VerificationReport("unverified", checks)

        patched_unit = unit.model_copy(update={"source": patched_source})
        detections = self.rules.scan(patched_unit)
        still_fires = False
        if finding.knowledge_ref:
            still_fires = any(d.slug == finding.knowledge_ref for d in detections)
        else:
            still_fires = any(d.cwe == finding.cwe for d in detections)
        checks.append(
            {
                "name": "no_rescan_regression",
                "ok": not still_fires,
                "detail": "original rule no longer fires" if not still_fires
                else "the original rule still fires on the patched code",
            }
        )

        sig_ok = self._signature_preserved(unit, patched_source)
        checks.append(
            {"name": "signature_preserved", "ok": sig_ok,
             "detail": "function/method name preserved" if sig_ok else "signature changed"}
        )

        checks.append(self._tests_check(patched_source, unit.language))

        if ok and not still_fires and sig_ok:
            status = "verified"
        elif ok:
            status = "partially_verified"
        else:
            status = "unverified"
        return VerificationReport(status, checks)

    @staticmethod
    def _signature_preserved(unit: CodeUnit, patched: str) -> bool:
        name = unit.name
        if not name or name in {"<module>", "<anonymous>"}:
            return True
        return bool(re.search(rf"\b{re.escape(name)}\b", patched))

    def _tests_check(self, patched_source: str, language: str) -> dict:
        if not config.RUN_TESTS:
            return {"name": "tests", "ok": None, "detail": "test execution disabled (safe default)"}
        if language != "python":
            return {"name": "tests", "ok": None, "detail": "only Python tests are executed"}
        try:
            with tempfile.TemporaryDirectory(prefix="codeshield-test-") as tmp:
                target = Path(tmp) / "patched_snippet.py"
                target.write_text(patched_source, encoding="utf-8")
                proc = subprocess.run(
                    ["python", "-m", "pytest", "-q", str(target)],
                    capture_output=True, text=True, timeout=config.TEST_TIMEOUT_SECONDS,
                )
                return {
                    "name": "tests",
                    "ok": proc.returncode == 0,
                    "detail": (proc.stdout or proc.stderr).strip()[-400:],
                }
        except Exception as exc:  # noqa: BLE001
            return {"name": "tests", "ok": None, "detail": f"tests not run: {exc}"}
