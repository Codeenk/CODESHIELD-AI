"""Deterministic, per-flaw patch templates.

Each template rewrites a recognised vulnerable construct into a safer form and
returns the new function source (never the whole file). Templates are heuristic
by design: the verifier — not the template — decides whether the result is
actually safe, so a template that fails to remove the flaw is labelled
*partially verified* rather than presented as a fix.
"""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass
from typing import Callable, Optional

from ..explain.explainer import REMEDIATION
from ..schemas import CodeUnit, Finding


@dataclass
class Template:
    slug: str
    name: str
    apply: Callable[[CodeUnit, Finding], Optional[dict]]
    semantic_risk: bool = False


def unified_diff(before: str, after: str, path: str = "function") -> str:
    diff = difflib.unified_diff(
        before.splitlines(), after.splitlines(),
        fromfile=f"a/{path}", tofile=f"b/{path}", lineterm="",
    )
    return "\n".join(diff)


def _ensure_python_import(source: str, statement: str) -> str:
    if statement in source:
        return source
    return statement + "\n" + source


# --------------------------------------------------------------------------- #
# Templates
# --------------------------------------------------------------------------- #
_SQL_RE = re.compile(
    r'(?P<recv>\w+)\.(?P<meth>execute\w*)\(\s*"(?P<sql>[^"]*)"\s*\+\s*(?P<var>[A-Za-z_]\w*)\s*\)'
)


def _sql_injection(unit: CodeUnit, finding: Finding) -> Optional[dict]:
    match = _SQL_RE.search(unit.source)
    if not match:
        return None
    placeholder_sql = match.group("sql").rstrip() + " ?"
    replacement = (
        f'{match.group("recv")}.{match.group("meth")}('
        f'"{placeholder_sql}", ({match.group("var")},))'
    )
    patched = unit.source[: match.start()] + replacement + unit.source[match.end():]
    return {
        "source": patched,
        "summary": "Parameterize the SQL query with a bound placeholder.",
        "rationale": REMEDIATION["sql_injection"],
    }


def _eval(unit: CodeUnit, finding: Finding) -> Optional[dict]:
    if not re.search(r"(?<![\w.])eval\s*\(", unit.source):
        return None
    patched = re.sub(r"(?<![\w.])eval\s*\(", "ast.literal_eval(", unit.source)
    patched = _ensure_python_import(patched, "import ast")
    return {
        "source": patched,
        "summary": "Replace eval() with ast.literal_eval().",
        "rationale": "literal_eval only accepts Python literals and cannot execute arbitrary code.",
    }


def _os_system(unit: CodeUnit, finding: Finding) -> Optional[dict]:
    match = re.search(r"os\.system\(\s*(?P<expr>.+?)\s*\)", unit.source)
    if not match:
        return None
    replacement = f"subprocess.run(shlex.split({match.group('expr')}), shell=False, check=False)"
    patched = unit.source[: match.start()] + replacement + unit.source[match.end():]
    patched = _ensure_python_import(patched, "import shlex")
    patched = _ensure_python_import(patched, "import subprocess")
    return {
        "source": patched,
        "summary": "Replace os.system with a no-shell subprocess call.",
        "rationale": "Passing an argument list with shell=False removes shell metacharacter injection.",
    }


_DESERIALIZE = re.compile(r"\b(pickle|cPickle|marshal|dill)\.loads?\s*\(")


def _deserialization(unit: CodeUnit, finding: Finding) -> Optional[dict]:
    if not _DESERIALIZE.search(unit.source):
        return None
    patched = _DESERIALIZE.sub("json.loads(", unit.source)
    patched = _ensure_python_import(patched, "import json")
    return {
        "source": patched,
        "summary": "Switch from pickle/marshal to json.loads.",
        "rationale": "Safe formats cannot execute code during deserialization. NOTE: changes the data format; migrate persisted payloads.",
    }


_WEAK_HASH = re.compile(r"\b(md5|sha1)\s*\(", re.IGNORECASE)


def _weak_hash(unit: CodeUnit, finding: Finding) -> Optional[dict]:
    if not _WEAK_HASH.search(unit.source):
        return None
    patched = _WEAK_HASH.sub("sha256(", unit.source)
    return {
        "source": patched,
        "summary": "Replace MD5/SHA-1 with SHA-256.",
        "rationale": REMEDIATION["cryptographic_failures"],
    }


_PY_SECRET = re.compile(
    r'(?P<name>\w*(?:password|passwd|secret|api[_-]?key|token|access[_-]?key)\w*)\s*=\s*"[^"]{6,}"',
    re.IGNORECASE,
)
_JS_SECRET = re.compile(
    r'(?P<kw>const|let|var)\s+(?P<name>\w*(?:password|secret|apiKey|token)\w*)\s*=\s*"[^"]{6,}"',
    re.IGNORECASE,
)
_JAVA_SECRET = re.compile(
    r'(?P<pre>String\s+)(?P<name>\w*(?:password|secret|token|key)\w*)\s*=\s*"[^"]{6,}"',
    re.IGNORECASE,
)


def _secret(unit: CodeUnit, finding: Finding) -> Optional[dict]:
    if unit.language == "python":
        if not _PY_SECRET.search(unit.source):
            return None
        patched = _PY_SECRET.sub(
            lambda m: f'{m.group("name")} = os.environ["{m.group("name").upper()}"]', unit.source
        )
        patched = _ensure_python_import(patched, "import os")
    elif unit.language in {"javascript", "typescript"}:
        if not _JS_SECRET.search(unit.source):
            return None
        patched = _JS_SECRET.sub(
            lambda m: f'{m.group("kw")} {m.group("name")} = process.env.{m.group("name").upper()}',
            unit.source,
        )
    else:
        if not _JAVA_SECRET.search(unit.source):
            return None
        patched = _JAVA_SECRET.sub(
            lambda m: f'{m.group("pre")}{m.group("name")} = System.getenv("{m.group("name").toUpperCase()}")',
            unit.source,
        )
    return {
        "source": patched,
        "summary": "Move the hard-coded secret into an environment variable.",
        "rationale": REMEDIATION["information_disclosure"] + " Rotate the exposed credential.",
    }


def _xss(unit: CodeUnit, finding: Finding) -> Optional[dict]:
    if not re.search(r"innerHTML\s*=", unit.source):
        return None
    patched = re.sub(r"\.innerHTML(\s*=)", r".textContent\1", unit.source)
    return {
        "source": patched,
        "summary": "Assign textContent instead of innerHTML.",
        "rationale": REMEDIATION["xss"],
    }


def _debug_flag(unit: CodeUnit, finding: Finding) -> Optional[dict]:
    if not re.search(r"DEBUG\s*=\s*True", unit.source):
        return None
    patched = re.sub(r"DEBUG\s*=\s*True", "DEBUG = False", unit.source)
    return {
        "source": patched,
        "summary": "Disable debug mode.",
        "rationale": REMEDIATION["information_disclosure"],
    }


def _advisory(unit: CodeUnit, finding: Finding) -> Optional[dict]:
    comment = "#" if unit.language == "python" else "//"
    guidance = REMEDIATION.get(finding.knowledge_ref or "", "Review and apply the framework's built-in defence.")
    lines = unit.source.splitlines()
    insert_at = 0
    if lines:
        # insert after the def/signature line when present
        for idx, line in enumerate(lines[:3]):
            insert_at = idx + 1
            break
    note = f"{comment} SECURITY (CodeShield): {finding.cwe} {finding.message} -> {guidance}"
    patched = "\n".join(lines[:insert_at] + [note] + lines[insert_at:])
    return {
        "source": patched,
        "summary": f"Advisory: {guidance}",
        "rationale": "No automatic rewrite was applied; this patch documents the required change.",
        "advisory": True,
    }


TEMPLATES: list[Template] = [
    Template("sql_injection", "parameterize-sql", _sql_injection),
    Template("rce", "literal-eval", _eval),
    Template("rce", "no-shell-subprocess", _os_system),
    Template("insecure_deserialization", "safe-deserialize", _deserialization, semantic_risk=True),
    Template("cryptographic_failures", "stronger-hash", _weak_hash),
    Template("information_disclosure", "env-secret", _secret, semantic_risk=True),
    Template("information_disclosure", "disable-debug", _debug_flag),
    Template("xss", "text-content", _xss),
]


def apply_templates(unit: CodeUnit, finding: Finding) -> list[dict]:
    results: list[dict] = []
    for template in TEMPLATES:
        if template.slug != (finding.knowledge_ref or ""):
            continue
        try:
            produced = template.apply(unit, finding)
        except Exception:  # noqa: BLE001
            produced = None
        if produced and produced.get("source") and produced["source"] != unit.source:
            produced.setdefault("name", template.name)
            produced["semantic_risk"] = template.semantic_risk
            results.append(produced)
    return results


def advisory_patch(unit: CodeUnit, finding: Finding) -> dict:
    produced = _advisory(unit, finding) or {
        "source": unit.source, "summary": "no change", "rationale": "", "advisory": True,
    }
    produced["name"] = "advisory"
    produced["semantic_risk"] = True
    return produced
