"""A small, transparent rule engine.

Each rule combines a dangerous *sink* pattern with optional *taint* indicators
and *safe* patterns that suppress it. This mirrors the precision-first posture
of the PRD: a vulnerable construct must be both reached and untrusted, and a
recognised safe form disables the finding. Every rule maps to a knowledge-base
slug so explanations can be grounded.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from ..schemas import CodeUnit, Evidence


@dataclass
class Detection:
    slug: str
    cwe: str
    rule_id: str
    message: str
    evidence: list[Evidence] = field(default_factory=list)
    base_confidence: float = 0.55
    severity_override: Optional[str] = None


@dataclass
class Rule:
    id: str
    slug: str
    cwe: str
    languages: tuple[str, ...]
    sink: str
    message: str
    taint: tuple[str, ...] = ()
    safe: tuple[str, ...] = ()
    base_confidence: float = 0.55
    severity_override: Optional[str] = None
    _sink_re: re.Pattern = field(init=False, repr=False)
    _taint_re: list = field(init=False, repr=False, default_factory=list)
    _safe_re: list = field(init=False, repr=False, default_factory=list)

    def __post_init__(self) -> None:
        # Be forgiving if a caller passes a bare string instead of a tuple.
        taint = (self.taint,) if isinstance(self.taint, str) else self.taint
        safe = (self.safe,) if isinstance(self.safe, str) else self.safe
        self._sink_re = re.compile(self.sink, re.IGNORECASE)
        self._taint_re = [re.compile(p, re.IGNORECASE) for p in taint]
        self._safe_re = [re.compile(p, re.IGNORECASE) for p in safe]


def _r(**kw) -> Rule:
    return Rule(**kw)


# Common "this value is attacker-controlled" indicators.
TAINT = (
    r"request\.(args|form|values|json|get_json|data|query_params|cookies|headers)",
    r"\binput\s*\(",
    r"sys\.argv",
    r"\bos\.environ",
    r"\breq\.(body|query|params|headers|cookies)",
    r"\brequest\.(body|query|params|headers|cookies)",
    r"getParameter|getHeader|HttpServletRequest",
    r"\bparams\b|\bkwargs\b|\bpayload\b",
    r"\+|%|\{.*\}|f[\"']",
)
CONCAT = (r"\+\s*\w|%\s*\(|\.format\s*\(|f[\"'].*\{", r"\+\s*(req|request|user|input|\w*param)", r"\$\{")

RULES: list[Rule] = [
    # ---- Injection -------------------------------------------------------
    _r(id="py-sql-concat", slug="sql_injection", cwe="CWE-89", languages=("python",),
       sink=r"(execute|executemany|raw)\s*\(\s*[^)]*(%|\+|\.format|f[\"'])",
       taint=CONCAT + TAINT,
       safe=(r"execute\s*\([^,)]*,\s*[\(\[]", r"\?|%s\s*[\"']\s*,", r"placeholder", r"paramstyle"),
       message="SQL query built with string concatenation/formatting instead of bound parameters.",
       base_confidence=0.7, severity_override="high"),
    _r(id="js-sql-concat", slug="sql_injection", cwe="CWE-89", languages=("javascript", "typescript"),
       sink=r"(query|execute|raw)\s*\(\s*[^)]*(\+\s*\w|\$\{)",
       taint=CONCAT + TAINT,
       safe=(r"\?\s*,", r"\$\d", r"placeholder", r"parameterized"),
       message="SQL query built with string interpolation instead of bound parameters.",
       base_confidence=0.7, severity_override="high"),
    _r(id="java-sql-concat", slug="sql_injection", cwe="CWE-89", languages=("java",),
       sink=r"(executeQuery|executeUpdate|createQuery|prepareStatement)\s*\([^)]*(\+\s*\w|\+)?",
       taint=(r'"\s*\+\s*\w', r"StringBuilder", r"concat"),
       safe=(r"prepareStatement\([^)]*\?[^)]*\)", r"\?\s*\)", r"setString\s*\("),
       message="SQL statement assembled with string concatenation instead of a parameterized statement.",
       base_confidence=0.6, severity_override="high"),
    _r(id="py-command-injection", slug="rce", cwe="CWE-78", languages=("python",),
       sink=r"(os\.(system|popen)|subprocess\.(run|call|check_output|Popen)|commands\.getoutput)\s*\(",
       taint=CONCAT + (r"shell\s*=\s*True",),
       safe=(r"shlex\.(quote|split)", r"shell\s*=\s*False", r"\[\s*[\"']"),
       message="OS command constructed from untrusted input.",
       base_confidence=0.65, severity_override="critical"),
    _r(id="py-eval-exec", slug="rce", cwe="CWE-95", languages=("python",),
       sink=r"\b(eval|exec|compile|__import__)\s*\(",
       taint=CONCAT + TAINT + (r"literal_eval",),
       safe=(r"ast\.literal_eval",),
       message="Dynamic code evaluation on a value that may be attacker-controlled.",
       base_confidence=0.6, severity_override="critical"),
    _r(id="js-eval-exec", slug="rce", cwe="CWE-95", languages=("javascript", "typescript"),
       sink=r"\b(eval|Function|setTimeout|setInterval)\s*\(\s*[^)]*(\+\s*\w|\$\{)",
       taint=CONCAT, safe=(), message="Dynamic code evaluation with interpolated input.",
       base_confidence=0.6, severity_override="critical"),
    _r(id="js-nosql-injection", slug="nosql_injection", cwe="CWE-943",
       languages=("javascript", "typescript"),
       sink=r"\.(find|findOne|update|deleteOne|deleteMany|aggregate)\s*\(\s*(req|request|params|query|body)",
       taint=TAINT, safe=(r"sanitize", r"validate"),
       message="MongoDB query object taken directly from the request without allow-listing.",
       base_confidence=0.55, severity_override="high"),
    _r(id="py-ssti", slug="ssti", cwe="CWE-1336", languages=("python",),
       sink=r"(render_template_string|from_string|Template)\s*\(",
       taint=CONCAT + TAINT, safe=(r"render_template\s*\(", r"SandboxedEnvironment"),
       message="User input rendered through a template engine (SSTI).",
       base_confidence=0.65, severity_override="high"),
    # ---- Path / files ----------------------------------------------------
    _r(id="py-path-traversal", slug="path_traversal_lfi_rfi", cwe="CWE-22", languages=("python",),
       sink=r"open\s*\(|send_file|send_from_directory|Path\s*\(",
       taint=CONCAT + TAINT + (r"\.\./",),
       safe=(r"secure_filename", r"os\.path\.abspath.*startswith", r"resolve\(\).*is_relative_to"),
       message="File path derived from user input without canonicalisation.",
       base_confidence=0.55, severity_override="high"),
    _r(id="py-xxe", slug="xxe", cwe="CWE-611", languages=("python",),
       sink=r"(etree|lxml|minidom|parse|fromstring)\s*\(",
       taint=TAINT, safe=(r"defusedxml", r"resolve_entities\s*=\s*False", r"XMLParser\(.*resolve_entities=False"),
       message="XML parsed with an entity-resolving parser (XXE).",
       base_confidence=0.5, severity_override="high"),
    # ---- Deserialization -------------------------------------------------
    _r(id="py-unsafe-deserialize", slug="insecure_deserialization", cwe="CWE-502", languages=("python",),
       sink=r"(pickle\.loads?|cPickle\.loads?|marshal\.loads?|dill\.loads?|yaml\.load)\s*\(",
       taint=(), safe=(r"yaml\.(safe_load|full_load)", r"Loader\s*=\s*(Safe|CSafe)Loader"),
       message="Untrusted data deserialized with an unsafe deserializer.",
       base_confidence=0.75, severity_override="high"),
    _r(id="java-deserialize", slug="insecure_deserialization", cwe="CWE-502", languages=("java",),
       sink=r"new\s+ObjectInputStream|readObject\s*\(|XMLDecoder",
       taint=(), safe=(r"ObjectInputFilter", r"ValidatingObjectInputStream"),
       message="Java native deserialization of untrusted data.",
       base_confidence=0.6, severity_override="high"),
    # ---- SSRF ------------------------------------------------------------
    _r(id="py-ssrf", slug="ssrf", cwe="CWE-918", languages=("python",),
       sink=r"(requests|httpx|urllib\.request|urlopen|session\.(get|post))\s*[.(]\s*[^)]*",
       taint=CONCAT + TAINT, safe=(r"allowlist|ALLOWED_HOSTS|validate_url|urlparse.*netloc\s*in",),
       message="Outbound request to a URL derived from user input.",
       base_confidence=0.5, severity_override="high"),
    _r(id="js-ssrf", slug="ssrf", cwe="CWE-918", languages=("javascript", "typescript"),
       sink=r"(fetch|axios\.(get|post)|http\.request|https\.request)\s*\(\s*[^)]*(\+\s*\w|\$\{)",
       taint=CONCAT, safe=(r"allowlist", r"ALLOWED", r"new URL\("),
       message="Outbound request built from user-controlled input.",
       base_confidence=0.5, severity_override="high"),
    # ---- XSS / browser ---------------------------------------------------
    _r(id="js-xss-innerhtml", slug="xss", cwe="CWE-79", languages=("javascript", "typescript"),
       sink=r"(innerHTML|outerHTML|document\.write|insertAdjacentHTML)\s*=",
       taint=CONCAT + TAINT, safe=(r"DOMPurify|textContent|escapeHtml|sanitize",),
       message="HTML sink assigned without output encoding or sanitisation.",
       base_confidence=0.6, severity_override="high"),
    _r(id="js-xss-express", slug="xss", cwe="CWE-79", languages=("javascript", "typescript"),
       sink=r"res\.(send|write|end)\s*\([^)]*(\+\s*\w|\$\{)",
       taint=CONCAT + TAINT, safe=(r"escape|sanitize|encodeURIComponent",),
       message="Response body built from user input without escaping.",
       base_confidence=0.5, severity_override="high"),
    _r(id="py-open-redirect", slug="open_redirect", cwe="CWE-601", languages=("python",),
       sink=r"(redirect|HttpResponseRedirect)\s*\(",
       taint=CONCAT + TAINT, safe=(r"url_has_allowed_host_and_scheme", r"is_safe_url"),
       message="Redirect target comes from user input.",
       base_confidence=0.55, severity_override="medium"),
    _r(id="js-prototype-pollution", slug="prototype_pollution", cwe="CWE-1321",
       languages=("javascript", "typescript"),
       sink=r"(Object\.assign|_\.merge|_\.defaultsDeep|deepMerge|\.set\s*\()\s*\([^)]*(req|request|body|params)",
       taint=TAINT, safe=(r"Object\.(freeze|create\(null\))", r"__proto__\s*===\s*undefined"),
       message="User-controlled object merged into a target without key allow-listing.",
       base_confidence=0.5, severity_override="high"),
    # ---- Secrets / info disclosure --------------------------------------
    _r(id="secret-hardcoded", slug="information_disclosure", cwe="CWE-798", languages=("python", "javascript", "typescript", "java"),
       sink=r"(password|passwd|secret|api[_-]?key|apikey|token|access[_-]?key|private[_-]?key)\s*[:=]\s*[\"'][^\"']{6,}[\"']",
       taint=(), safe=(r"os\.environ|process\.env|getenv|System\.getenv|\$\{|placeholder|example|dummy|changeme", r"[\"']{2}"),
       message="Hard-coded credential or secret literal in source.",
       base_confidence=0.6, severity_override="high"),
    _r(id="py-debug-true", slug="information_disclosure", cwe="CWE-489", languages=("python",),
       sink=r"(DEBUG|debug)\s*=\s*True", taint=(), safe=(),
       message="Debug mode enabled; may expose stack traces and internals.",
       base_confidence=0.45, severity_override="medium"),
    # ---- Weak crypto (mapped via default taxonomy) ----------------------
    _r(id="weak-hash", slug="cryptographic_failures", cwe="CWE-328", languages=("python", "javascript", "typescript", "java"),
       sink=r"\b(md5|sha1|MD5|SHA1|SHA-1|DES|RC4)\b",
       taint=(), safe=(r"password_hash|bcrypt|argon2|scrypt|pbkdf2|SHA-?256|SHA-?512",),
       message="Weak or broken cryptographic primitive in use.",
       base_confidence=0.45, severity_override="medium"),
    # ---- TOCTOU ----------------------------------------------------------
    _r(id="py-toctou", slug="race_conditions", cwe="CWE-367", languages=("python",),
       sink=r"os\.path\.exists\s*\(|os\.access\s*\(",
       taint=(), safe=(),
       message="Check-then-use on the filesystem is vulnerable to a TOCTOU race.",
       base_confidence=0.35, severity_override="medium"),
]


class RuleEngine:
    """Apply every language-compatible rule to a code unit."""

    def __init__(self, rules: Optional[list[Rule]] = None) -> None:
        self.rules = rules if rules is not None else RULES

    def scan(self, unit: CodeUnit) -> list[Detection]:
        lines = unit.source.splitlines()
        detections: list[Detection] = []
        unit_text = unit.source
        for rule in self.rules:
            if unit.language not in rule.languages:
                continue
            evidence: list[Evidence] = []
            for idx, line in enumerate(lines, start=1):
                if not rule._sink_re.search(line):
                    continue
                if any(p.search(line) for p in rule._safe_re):
                    continue
                if rule._taint_re:
                    if not any(p.search(line) or p.search(unit_text) for p in rule._taint_re):
                        continue
                evidence.append(
                    Evidence(
                        line=unit.start_line + idx - 1,
                        snippet=line.strip()[:200],
                        reason=f"matches rule {rule.id}",
                        weight=1.0,
                    )
                )
            if evidence:
                detections.append(
                    Detection(
                        slug=rule.slug,
                        cwe=rule.cwe,
                        rule_id=rule.id,
                        message=rule.message,
                        evidence=evidence,
                        base_confidence=rule.base_confidence,
                        severity_override=rule.severity_override,
                    )
                )
        return detections
