"""CWE knowledge + severity mapping.

A single, explicit table keeps severity assignment deterministic and auditable — the PRD
(FR-12) requires severity derived from CWE class and confidence, not from a black box.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..models import Severity


@dataclass(frozen=True)
class CweInfo:
    cwe: str
    name: str
    severity: Severity
    owasp: str
    category: str


_CWE_TABLE: dict[str, CweInfo] = {
    "CWE-89": CweInfo("CWE-89", "SQL Injection", Severity.critical, "A03:2021", "Injection"),
    "CWE-78": CweInfo(
        "CWE-78", "OS Command Injection", Severity.critical, "A03:2021", "Injection"
    ),
    "CWE-94": CweInfo("CWE-94", "Code Injection", Severity.critical, "A03:2021", "Injection"),
    "CWE-95": CweInfo(
        "CWE-95", "Eval Injection", Severity.critical, "A03:2021", "Injection"
    ),
    "CWE-502": CweInfo(
        "CWE-502",
        "Deserialization of Untrusted Data",
        Severity.critical,
        "A08:2021",
        "Insecure Deserialization",
    ),
    "CWE-798": CweInfo(
        "CWE-798", "Use of Hard-coded Credentials", Severity.high, "A07:2021", "Auth Failures"
    ),
    "CWE-22": CweInfo(
        "CWE-22", "Path Traversal", Severity.high, "A01:2021", "Broken Access Control"
    ),
    "CWE-918": CweInfo(
        "CWE-918", "Server-Side Request Forgery (SSRF)", Severity.high, "A10:2021", "SSRF"
    ),
    "CWE-79": CweInfo(
        "CWE-79", "Cross-site Scripting (XSS)", Severity.high, "A03:2021", "Injection"
    ),
    "CWE-327": CweInfo(
        "CWE-327",
        "Use of a Broken or Risky Cryptographic Algorithm",
        Severity.medium,
        "A02:2021",
        "Cryptographic Failures",
    ),
    "CWE-328": CweInfo(
        "CWE-328", "Use of Weak Hash", Severity.medium, "A02:2021", "Cryptographic Failures"
    ),
    "CWE-330": CweInfo(
        "CWE-330",
        "Use of Insufficiently Random Values",
        Severity.medium,
        "A02:2021",
        "Cryptographic Failures",
    ),
    "CWE-1333": CweInfo(
        "CWE-1333",
        "Inefficient Regular Expression Complexity",
        Severity.medium,
        "A03:2021",
        "Injection",
    ),
    "CWE-120": CweInfo(
        "CWE-120",
        "Buffer Copy without Checking Size of Input",
        Severity.high,
        "A06:2021",
        "Vulnerable Components",
    ),
}

_UNKNOWN = CweInfo("CWE-000", "Uncategorized Weakness", Severity.medium, "A00:2021", "Other")


def cwe_info(cwe: str) -> CweInfo:
    """Return the metadata for a CWE id, falling back to a neutral entry."""
    if not cwe:
        return _UNKNOWN
    key = cwe.strip().upper()
    if not key.startswith("CWE-"):
        key = f"CWE-{key}"
    return _CWE_TABLE.get(key, _cwe_info_from_name(key))


def _cwe_info_from_name(cwe: str) -> CweInfo:
    return CweInfo(cwe, "Uncategorized Weakness", Severity.medium, "A00:2021", "Other")


def severity_for(cwe: str, confidence: float = 0.8) -> Severity:
    """Deterministic severity from CWE class, nudged down when confidence is low.

    A high-confidence finding keeps its base severity; a low-confidence finding is capped
    at medium so the dashboard does not cry wolf on uncertain model output.
    """
    base = cwe_info(cwe).severity
    if confidence < 0.4 and base.rank >= Severity.high.rank:
        return Severity.medium
    return base


def known_cwes() -> list[str]:
    return sorted(_CWE_TABLE.keys())


def all_cwe_info() -> dict[str, CweInfo]:
    return dict(_CWE_TABLE)


def owasp_for(cwe: str) -> str:
    return cwe_info(cwe).owasp


def normalize_cwe(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip().upper()
    return value if value.startswith("CWE-") else f"CWE-{value}"
