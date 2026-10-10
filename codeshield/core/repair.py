"""Stage 5 — repair (PRD §7.5 FR-19..FR-24, §11.3).

Patch generation is layered:

1. **Template fixers** — deterministic, CWE-specific rewrites for the patterns the rule set
   knows (e.g. ``os.system`` -> ``subprocess.run(..., shell=False)``). Always available, no key.
2. **LLM repair** — an optional OpenAI-compatible endpoint for Qwen2.5-Coder. Used only when
   configured; its output is treated as an unverified candidate.
3. **Guidance candidate** — a safe-pattern stub with a TODO when no transform applies, always
   marked unverified.

Nothing here decides a patch is safe — that is ``verify.py``'s job, and the orchestrator only
presents patches after verification (FR-21, FR-23).
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass

from ..config import Settings, get_settings
from ..models import Finding, Patch, PatchStatus
from .parsing import FileAnalysis
from .rules import mask_secrets


@dataclass
class Candidate:
    patch: Patch
    patched_text: str


def _replace_region(analysis: FileAnalysis, finding: Finding, replacement: list[str]) -> str:
    lines = list(analysis.lines)
    start = finding.location.start_line - 1
    end = finding.location.end_line
    lines[start:end] = replacement
    text = "\n".join(lines)
    if analysis.text.endswith("\n"):
        text += "\n"
    return text


def _unified_diff(original: str, patched: str, path: str) -> str:
    diff = difflib.unified_diff(
        original.splitlines(),
        patched.splitlines(),
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
        lineterm="",
    )
    return "\n".join(diff)


def _flagged_lines(analysis: FileAnalysis, finding: Finding) -> list[str]:
    start = max(1, finding.location.start_line) - 1
    end = min(len(analysis.lines), finding.location.end_line)
    return list(analysis.lines[start:end])


# --------------------------------------------------------------------------- #
# Template fixers
# --------------------------------------------------------------------------- #


def _fix_sql(lines: list[str], finding: Finding) -> tuple[list[str], str] | None:
    """Turn an f-string/%-formatted query into a parameterised one where we can."""
    joined = "\n".join(lines)
    # f-string form: execute(f"...{var}...") -> execute("... ?", (var,))
    fstring = re.search(r"""(?P<call>\w+)\s*\(\s*f(["'])(?P<body>.*?)\2\s*\)""", joined, re.DOTALL)
    if fstring:
        body = fstring.group("body")
        vars_ = re.findall(r"\{([^{}]+)\}", body)
        if vars_:
            safe = re.sub(r"\{[^{}]+\}", "?", body)
            params = ", ".join(v.strip() for v in vars_)
            replacement = f'{fstring.group("call")}("{safe}", ({params},))'
            return [re.sub(re.escape(fstring.group(0)), replacement, joined)], (
                "Use a parameterised query with bound parameters"
            )
    return None


def _fix_os_command(lines: list[str], finding: Finding) -> tuple[list[str], str]:
    joined = "\n".join(lines)
    joined = re.sub(
        r"\bos\.system\s*\((?P<arg>.+?)\)",
        r"subprocess.run(shlex.split(\g<arg>), shell=False, check=True)",
        joined,
    )
    joined = re.sub(
        r"\bos\.popen\s*\((?P<arg>.+?)\)",
        r"subprocess.Popen(shlex.split(\g<arg>), shell=False)",
        joined,
    )
    joined = joined.replace("shell=True", "shell=False")
    return joined.splitlines(), "Avoid the shell and pass an argument list (shell=False)"


def _fix_eval(lines: list[str], finding: Finding) -> tuple[list[str], str]:
    joined = "\n".join(lines)
    if finding.cwe == "CWE-95" and any("eval(" in ln for ln in lines) and not any(
        "=" in ln for ln in lines
    ):
        joined = re.sub(r"\beval\s*\(", "json.loads(", joined)
        return joined.splitlines(), "Replace eval with a safe parser (json.loads)"
    joined = re.sub(r"(?<![\w.])eval\s*\(", "ast.literal_eval(", joined)
    return joined.splitlines(), "Replace eval with ast.literal_eval"


def _fix_innerhtml(lines: list[str], finding: Finding) -> tuple[list[str], str]:
    joined = "\n".join(lines)
    joined = re.sub(r"\.innerHTML\s*=", ".textContent =", joined)
    joined = re.sub(r"\.outerHTML\s*=", ".textContent =", joined)
    joined = re.sub(r"document\.write(?:ln)?\s*\(", "document.createElement(", joined)
    return joined.splitlines(), "Write text, not HTML (textContent) or sanitise with DOMPurify"


def _fix_deserialization(lines: list[str], finding: Finding) -> tuple[list[str], str]:
    joined = "\n".join(lines)
    joined = re.sub(r"\b(?:pickle|cPickle|marshal|dill)\.loads?\s*\(", "json.loads(", joined)
    joined = re.sub(r"\byaml\.load\s*\(", "yaml.safe_load(", joined)
    return joined.splitlines(), "Use a safe deserialisation format (JSON / SafeLoader)"


def _fix_weak_hash(lines: list[str], finding: Finding) -> tuple[list[str], str]:
    joined = "\n".join(lines)
    joined = re.sub(r"hashlib\.md5\s*\(", "hashlib.sha256(", joined)
    joined = re.sub(r"hashlib\.sha1\s*\(", "hashlib.sha256(", joined)
    joined = re.sub(r"createHash\s*\(\s*['\"]md5['\"]\s*\)", "createHash('sha256')", joined)
    joined = re.sub(r"createHash\s*\(\s*['\"]sha1['\"]\s*\)", "createHash('sha256')", joined)
    return joined.splitlines(), "Use SHA-256 (or bcrypt/argon2 for passwords)"


def _fix_secret(lines: list[str], finding: Finding) -> tuple[list[str], str]:
    joined = "\n".join(lines)

    def repl(match: re.Match) -> str:
        key = re.sub(r"[^A-Za-z0-9]", "_", match.group("key")).upper()
        return f'{match.group("key")} = os.environ["{key}"]'

    joined = re.sub(
        r"""(?P<key>[A-Za-z_][\w]*)\s*=\s*["'][^"'\s]{4,}["']""",
        repl,
        joined,
    )
    return joined.splitlines(), "Load the secret from the environment and rotate the leaked value"


_TEMPLATE_FIXERS = {
    "CWE-89": ("parameterise the query", _fix_sql),
    "CWE-78": ("remove the shell", _fix_os_command),
    "CWE-95": ("replace dynamic evaluation", _fix_eval),
    "CWE-79": ("escape output", _fix_innerhtml),
    "CWE-502": ("safe deserialisation", _fix_deserialization),
    "CWE-328": ("stronger hash", _fix_weak_hash),
    "CWE-798": ("move the secret out of source", _fix_secret),
}


def _template_candidate(finding: Finding, analysis: FileAnalysis) -> Candidate | None:
    entry = _TEMPLATE_FIXERS.get(finding.cwe)
    lines = _flagged_lines(analysis, finding)
    if not lines:
        return None

    if entry is None:
        summary = "apply the recommended remediation for this weakness"
        replacement = list(lines)
    else:
        summary, fixer = entry
        result = fixer(lines, finding)
        if result is None:
            replacement = list(lines)
        else:
            replacement, summary = result
            if replacement == lines:
                return None

    original = "\n".join(lines)
    patched = "\n".join(replacement)
    if patched == original:
        return None

    patched_text = _replace_region(analysis, finding, replacement)
    patch = Patch(
        finding_id=finding.id,
        status=PatchStatus.unverified,  # promoted by verify.py
        summary=summary,
        original_code=original,
        patched_code=patched,
        diff=_unified_diff(original, patched, finding.file),
        verification=[],
        source="template",
        rank=0,
    )
    return Candidate(patch=patch, patched_text=patched_text)


def _guidance_candidate(finding: Finding, analysis: FileAnalysis) -> Candidate:
    """A conservative, commented stub so the user still gets actionable next steps."""
    lines = _flagged_lines(analysis, finding)
    original = "\n".join(lines)
    indent = re.match(r"\s*", lines[0]).group(0) if lines else ""
    replacement = [
        f"{indent}# FIXME(CodeShield): {finding.remediation or finding.rationale}",
        *lines,
    ]
    patched = "\n".join(replacement)
    patched_text = _replace_region(analysis, finding, replacement)
    patch = Patch(
        finding_id=finding.id,
        status=PatchStatus.unverified,
        summary="add a remediation TODO (no automatic rewrite available)",
        original_code=original,
        patched_code=patched,
        diff=_unified_diff(original, patched, finding.file),
        verification=["No automatic rewrite for this pattern; guidance stub only."],
        source="template",
        rank=0,
    )
    return Candidate(patch=patch, patched_text=patched_text)


# --------------------------------------------------------------------------- #
# LLM candidate (optional)
# --------------------------------------------------------------------------- #

_LLM_PROMPT = """You are a secure-code repair assistant. Rewrite ONLY the flagged span so the
{CWE} ({name}) weakness is fixed. Preserve the function signature and public behaviour.
Return the corrected code with no markdown fences and no commentary.

Code:
{code}
"""


def _llm_candidate(
    finding: Finding, analysis: FileAnalysis, settings: Settings
) -> Candidate | None:
    if not settings.repair_endpoint:
        return None
    lines = _flagged_lines(analysis, finding)
    original = "\n".join(lines)
    prompt = _LLM_PROMPT.format(
        CWE=finding.cwe, name=finding.cwe_name, code=original
    )
    try:  # pragma: no cover - network dependent
        import httpx

        headers = {"Content-Type": "application/json"}
        if settings.repair_api_key:
            headers["Authorization"] = f"Bearer {settings.repair_api_key}"
        response = httpx.post(
            settings.repair_endpoint,
            headers=headers,
            json={
                "model": settings.repair_model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
            },
            timeout=60,
        )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"].strip()
        content = re.sub(r"^```[a-zA-Z]*\n|```$", "", content).strip()
    except Exception:
        return None

    if not content or content == original:
        return None
    replacement = content.splitlines()
    patched_text = _replace_region(analysis, finding, replacement)
    patch = Patch(
        finding_id=finding.id,
        status=PatchStatus.unverified,
        summary=f"LLM repair ({settings.repair_model})",
        original_code=original,
        patched_code=content,
        diff=_unified_diff(original, content, finding.file),
        verification=[],
        source="llm",
        rank=1,
    )
    return Candidate(patch=patch, patched_text=patched_text)


def generate_candidates(
    finding: Finding, analysis: FileAnalysis, settings: Settings | None = None, limit: int = 3
) -> list[Candidate]:
    """Produce ranked candidate patches for one finding (FR-20).

    Order: template fix, LLM fix, guidance stub. Candidates are deduplicated on the patched
    text. Verification and final ranking happen in ``verify.py`` / the orchestrator.
    """
    settings = settings or get_settings()
    candidates: list[Candidate] = []
    seen: set[str] = set()

    for candidate in (
        _template_candidate(finding, analysis),
        _llm_candidate(finding, analysis, settings),
    ):
        if candidate and candidate.patch.patched_code not in seen:
            seen.add(candidate.patch.patched_code)
            candidates.append(candidate)

    if not candidates:
        guidance = _guidance_candidate(finding, analysis)
        candidates.append(guidance)

    for i, candidate in enumerate(candidates):
        candidate.patch.rank = i
    return candidates[:limit]


def redact(text: str) -> str:
    """Redact secrets from any text that will be displayed or stored."""
    return mask_secrets(text)
