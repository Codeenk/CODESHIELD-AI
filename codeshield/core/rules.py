"""Stage 3a — rule-based baseline (PRD §7.3 FR-13, §11.4).

A curated, auditable rule set that runs with zero dependencies and acts as the
precision-first cross-check against the neural detector. Rules are intentionally
conservative: each pattern maps to a CWE, a severity and a remediation, and produces a
stable fingerprint so a project's false-positive memory (FR-14) can suppress it later.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass

from ..models import AttentionLine, Engine, Finding, Location
from .parsing import detect_language, snippet_for
from .severity import cwe_info

ALL_LANGS = ("python", "javascript", "typescript", "java")

_SECRET_KEY = (
    r"(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|private[_-]?key|"
    r"auth[_-]?token|token|client[_-]?secret)"
)


@dataclass(frozen=True)
class Rule:
    id: str
    cwe: str
    title: str
    pattern: re.Pattern
    languages: tuple[str, ...]
    rationale: str
    exploit: str
    remediation: str
    node_kind: str = "call"
    confidence: float = 0.85
    severity_override: str | None = None
    mask: bool = False


def _r(pattern: str, flags: int = re.MULTILINE) -> re.Pattern:
    return re.compile(pattern, flags)


# --------------------------------------------------------------------------- #
# Rule set
# --------------------------------------------------------------------------- #

RULES: list[Rule] = [
    # -------- CWE-89 SQL injection --------
    Rule(
        id="CS-SQL-001",
        cwe="CWE-89",
        title="SQL query built with string interpolation",
        pattern=_r(
            r"""(?:execute|executemany|executescript|raw|query)\s*\(\s*(?:f["']|["'][^"']*["']\s*(?:%|\+))"""
        ),
        languages=ALL_LANGS,
        rationale=(
            "SQL is assembled from a string literal + variables. Untrusted input flows directly "
            "into the statement, so an attacker can alter the query structure."
        ),
        exploit="A username of `' OR '1'='1` turns the filter into a tautology and returns every row.",
        remediation="Use a parameterised query (placeholder + bound parameters) instead of building SQL.",
        node_kind="binary_expression",
        confidence=0.9,
    ),
    Rule(
        id="CS-SQL-002",
        cwe="CWE-89",
        title="SQL query concatenated with request/user data",
        pattern=_r(
            r"""(?:execute|query|raw)\s*\([^)\n]*\+\s*(?:request|req\.|input\s*\(|params|user|argv)"""
        ),
        languages=ALL_LANGS,
        rationale="A request/user value is concatenated directly into a SQL string.",
        exploit="Concatenating `?id=<value>` lets an attacker inject a `UNION SELECT` clause.",
        remediation="Bind the untrusted value as a parameter; never concatenate it into SQL.",
        node_kind="binary_expression",
    ),
    # -------- CWE-78 OS command injection --------
    Rule(
        id="CS-CMD-001",
        cwe="CWE-78",
        title="Shell command executed with os.system/os.popen",
        pattern=_r(r"\bos\.(?:system|popen)\s*\("),
        languages=("python",),
        rationale="os.system/os.popen run a command string through the shell; embedded input is executed.",
        exploit="A filename of `; rm -rf /` is executed as a second command.",
        remediation="Use subprocess with an argument list and shell=False, or avoid the shell entirely.",
        node_kind="call",
        confidence=0.9,
    ),
    Rule(
        id="CS-CMD-002",
        cwe="CWE-78",
        title="subprocess invoked with shell=True",
        pattern=_r(r"\bsubprocess\.(?:run|call|check_call|check_output|Popen)\s*\([^)\n]*shell\s*=\s*True"),
        languages=("python",),
        rationale="shell=True hands the command string to the system shell, enabling command injection.",
        exploit="`host = 'x; cat /etc/passwd'` runs the injected command.",
        remediation="Pass a list of arguments and use shell=False (the default).",
        node_kind="keyword_argument",
        confidence=0.92,
    ),
    Rule(
        id="CS-CMD-003",
        cwe="CWE-78",
        title="child_process.exec with dynamic input",
        pattern=_r(r"\bchild_process\.(?:exec|execSync)\s*\("),
        languages=("javascript", "typescript"),
        rationale="child_process.exec spawns a shell; interpolated input can inject commands.",
        exploit="`exec('ping ' + host)` with `host='; id'` executes `id`.",
        remediation="Use child_process.execFile/spawn with an argument array and no shell.",
        node_kind="call",
        confidence=0.85,
    ),
    Rule(
        id="CS-CMD-004",
        cwe="CWE-78",
        title="Runtime.exec / ProcessBuilder with dynamic input",
        pattern=_r(r"(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\("),
        languages=("java",),
        rationale="Executing a command built from untrusted input allows OS command injection.",
        exploit="Passing user input as the program argument executes arbitrary commands.",
        remediation="Validate input against an allow-list and avoid passing untrusted data to the shell.",
        node_kind="call",
        confidence=0.8,
    ),
    # -------- CWE-95 eval / code injection --------
    Rule(
        id="CS-EVAL-001",
        cwe="CWE-95",
        title="Dynamic code evaluation",
        pattern=_r(r"\b(?:eval|exec)\s*\(\s*(?!['\"]\s*\))"),
        languages=("python",),
        rationale="eval()/exec() execute a string as Python. Untrusted input becomes arbitrary code execution.",
        exploit="`eval(request.args['expr'])` runs whatever the caller sends.",
        remediation="Replace eval with a safe parser (e.g. ast.literal_eval) or an explicit dispatch table.",
        node_kind="call",
        confidence=0.85,
    ),
    Rule(
        id="CS-EVAL-002",
        cwe="CWE-95",
        title="JavaScript eval / Function constructor",
        pattern=_r(r"\b(?:eval|Function)\s*\("),
        languages=("javascript", "typescript"),
        rationale="eval() and the Function constructor execute strings as code.",
        exploit="eval() on user input is a direct remote code execution primitive.",
        remediation="Parse data with JSON.parse or a schema validator; never eval input.",
        node_kind="call",
        confidence=0.8,
    ),
    # -------- CWE-79 XSS --------
    Rule(
        id="CS-XSS-001",
        cwe="CWE-79",
        title="Unescaped HTML written to the DOM",
        pattern=_r(r"\.(?:innerHTML|outerHTML)\s*=|document\.write(?:ln)?\s*\(|dangerouslySetInnerHTML"),
        languages=("javascript", "typescript"),
        rationale="Writing HTML from variables into the DOM renders attacker-controlled markup as script.",
        exploit="`el.innerHTML = '<img src=x onerror=alert(document.cookie)>'` steals cookies.",
        remediation="Use textContent, or sanitise the HTML with a library such as DOMPurify.",
        node_kind="assignment",
    ),
    Rule(
        id="CS-XSS-002",
        cwe="CWE-79",
        title="HTTP response built from request parameter",
        pattern=_r(
            r"""(?:getWriter\(\)|PrintWriter|response\.getOutputStream\(\))[^;\n]*\.(?:print|println|write)\s*\([^)\n]*(?:request\.getParameter|getQueryString)"""
        ),
        languages=("java",),
        rationale="Reflecting a request parameter into the response without encoding enables reflected XSS.",
        exploit="`?name=<script>...</script>` is echoed verbatim into the page.",
        remediation="HTML-encode all reflected values (e.g. OWASP Java Encoder).",
        node_kind="method_invocation",
        confidence=0.8,
    ),
    # -------- CWE-502 insecure deserialization --------
    Rule(
        id="CS-DESER-001",
        cwe="CWE-502",
        title="Unsafe deserialization with pickle/marshal",
        pattern=_r(r"\b(?:pickle|cPickle|marshal|dill)\.loads?\s*\("),
        languages=("python",),
        rationale="pickle/marshal execute arbitrary code while unpickling, so untrusted payloads are RCE.",
        exploit="A crafted pickle calls os.system during __reduce__.",
        remediation="Use a safe format (JSON, MessagePack) or a restricted unpickler.",
        node_kind="call",
        confidence=0.9,
    ),
    Rule(
        id="CS-DESER-002",
        cwe="CWE-502",
        title="yaml.load without a safe loader",
        pattern=_r(r"\byaml\.load\s*\((?![^)\n]*SafeLoader)[^)\n]*\)"),
        languages=("python",),
        rationale="yaml.load with the default loader can construct arbitrary Python objects.",
        exploit="A `!!python/object/apply:os.system` tag executes commands at load time.",
        remediation="Use yaml.safe_load / yaml.load(..., Loader=yaml.SafeLoader).",
        node_kind="call",
        confidence=0.85,
    ),
    Rule(
        id="CS-DESER-003",
        cwe="CWE-502",
        title="Java ObjectInputStream on untrusted data",
        pattern=_r(r"new\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\)"),
        languages=("java",),
        rationale="Deserialising untrusted bytes with ObjectInputStream enables gadget-chain code execution.",
        exploit="A malicious serialized stream triggers a gadget chain such as CommonsCollections.",
        remediation="Avoid native Java serialization; use a safe format and validate types.",
        node_kind="object_creation",
        confidence=0.8,
    ),
    # -------- CWE-798 hardcoded credentials --------
    Rule(
        id="CS-SECRET-001",
        cwe="CWE-798",
        title="Hard-coded credential or secret",
        pattern=_r(rf"""(?:{_SECRET_KEY})\s*[:=]\s*["'][^"'\s]{{4,}}["']""", re.IGNORECASE | re.MULTILINE),
        languages=ALL_LANGS,
        rationale="A password/API key is embedded in source. Anyone with the repo has the credential.",
        exploit="A leaked API key allows an attacker to impersonate the application.",
        remediation="Load secrets from the environment or a secret manager; rotate the leaked value.",
        node_kind="assignment",
        confidence=0.8,
        mask=True,
    ),
    # -------- CWE-22 path traversal --------
    Rule(
        id="CS-PATH-001",
        cwe="CWE-22",
        title="File path built from untrusted input",
        pattern=_r(
            r"""(?:open|read_file|send_file|FileInputStream|FileReader|Files\.readAllBytes)\s*\([^)\n]*(?:request|req\.(?:query|params|body)|input\s*\(|sys\.argv|params\[)"""
        ),
        languages=ALL_LANGS,
        rationale="A file path derived from user input can escape the intended directory.",
        exploit="`?file=../../etc/passwd` reads a file outside the web root.",
        remediation="Resolve the path and verify it stays inside an allow-listed base directory.",
        node_kind="call",
        confidence=0.75,
    ),
    # -------- CWE-918 SSRF --------
    Rule(
        id="CS-SSRF-001",
        cwe="CWE-918",
        title="Outbound request to a user-controlled URL",
        pattern=_r(
            r"""(?:requests\.(?:get|post|put|delete|head)|urllib\.request\.urlopen|axios\.(?:get|post)|fetch)\s*\([^)\n]*(?:request|req\.(?:query|body|params)|input\s*\(|params\[)"""
        ),
        languages=ALL_LANGS,
        rationale="Fetching a URL supplied by the user lets an attacker reach internal services.",
        exploit="`?url=http://169.254.169.254/latest/meta-data/` leaks cloud metadata credentials.",
        remediation="Validate the URL against an allow-list and block private/link-local ranges.",
        node_kind="call",
        confidence=0.75,
    ),
    # -------- CWE-328 weak hash --------
    Rule(
        id="CS-CRYPTO-001",
        cwe="CWE-328",
        title="Weak hash algorithm (MD5/SHA-1)",
        pattern=_r(
            r"""hashlib\.(?:md5|sha1)\s*\(|MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1)["']|createHash\s*\(\s*["'](?:md5|sha1)["']"""
        ),
        languages=ALL_LANGS,
        rationale="MD5 and SHA-1 are collision-broken and unsuitable for integrity or password hashing.",
        exploit="Collisions let an attacker forge a file/password that hashes identically.",
        remediation="Use SHA-256+ for integrity and bcrypt/scrypt/argon2 for passwords.",
        node_kind="call",
    ),
    # -------- CWE-327 broken crypto --------
    Rule(
        id="CS-CRYPTO-002",
        cwe="CWE-327",
        title="Broken or risky cipher (DES/RC4/ECB)",
        pattern=_r(
            r"""Cipher\.getInstance\s*\(\s*["'](?:DES|DESede|RC2|RC4|Blowfish|AES/ECB)|Crypto\.Cipher\.(?:DES|ARC4|Blowfish)\s*\(|\bECB\b"""
        ),
        languages=ALL_LANGS,
        rationale="DES/RC4 are broken and ECB reveals plaintext structure.",
        exploit="ECB leaks repeated blocks; brute-forcing DES is feasible.",
        remediation="Use AES-GCM or ChaCha20-Poly1305 with a random nonce.",
        node_kind="call",
        confidence=0.75,
    ),
    # -------- CWE-330 insecure randomness --------
    Rule(
        id="CS-RAND-001",
        cwe="CWE-330",
        title="Non-cryptographic randomness used for a security value",
        pattern=_r(
            r"""(?:token|secret|otp|nonce|session|salt|password|reset|csrf|code)\w*\s*[:=][^;\n]{0,60}(?:random\.(?:random|randint|choice|randrange)|Math\.random\s*\()"""
        ),
        languages=ALL_LANGS,
        rationale="random/Math.random are predictable and must not generate security tokens.",
        exploit="An attacker predicts the next token and hijacks a session.",
        remediation="Use secrets.token_urlsafe / crypto.randomBytes / SecureRandom.",
        node_kind="assignment",
        confidence=0.7,
    ),
]


def _rules_for(language: str) -> Iterable[Rule]:
    for rule in RULES:
        if language in rule.languages:
            yield rule


def mask_secrets(text: str) -> str:
    """Mask secret-looking values so they never appear in the UI or a report (§9)."""
    pattern = re.compile(
        rf"""((?:{_SECRET_KEY})\s*[:=]\s*["'])([^"'\s]{{2,}})(["'])""",
        re.IGNORECASE,
    )
    return pattern.sub(lambda m: f"{m.group(1)}{'*' * 8}{m.group(3)}", text)


def fingerprint_for(rule_id: str, path: str, line_text: str) -> str:
    basis = f"{rule_id}|{path}|{line_text.strip()}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def scan_text(path: str, text: str, language: str | None = None) -> list[Finding]:
    """Run every applicable rule over one file's text and return findings."""
    language = language or detect_language(path) or "text"
    if language == "text":
        return []

    lines = text.splitlines()
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    for rule in _rules_for(language):
        for match in rule.pattern.finditer(text):
            start_line = text.count("\n", 0, match.start()) + 1
            end_line = text.count("\n", 0, match.end()) + 1
            key = (rule.id, start_line)
            if key in seen:
                continue
            seen.add(key)

            info = cwe_info(rule.cwe)
            line_text = lines[start_line - 1] if 1 <= start_line <= len(lines) else ""
            raw_snippet = snippet_for(lines, start_line, end_line)
            snippet = mask_secrets(raw_snippet) if rule.mask else raw_snippet

            findings.append(
                Finding(
                    file=path,
                    location=Location(file=path, start_line=start_line, end_line=end_line),
                    cwe=rule.cwe,
                    cwe_name=info.name,
                    severity=info.severity,
                    confidence=rule.confidence,
                    engine=Engine.rules,
                    title=rule.title,
                    rationale=rule.rationale,
                    exploit=rule.exploit,
                    remediation=rule.remediation,
                    snippet=snippet,
                    syntax_nodes=[rule.node_kind],
                    attention=[AttentionLine(line=start_line, score=rule.confidence)],
                    owasp=info.owasp,
                    fingerprint=fingerprint_for(rule.id, path, line_text),
                )
            )

    return findings
