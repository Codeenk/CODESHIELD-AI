"""Secret masking used before anything is persisted, logged, or exported."""
from __future__ import annotations

import re
from typing import Any

_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token"
    r"|refresh[_-]?token|token|client[_-]?secret|private[_-]?key)\b"
    r"(\s*[:=]\s*)([\"'])([^\"'\n]{3,})\3"
)
_URL_CREDENTIALS = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^\s:/@]+:)([^\s/@]+)(@)")
_KNOWN = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{30,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
]
_PEM = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
    re.DOTALL,
)
REDACTED = "[REDACTED]"


def mask_text(text: str) -> str:
    if not text:
        return text
    masked = _PEM.sub(f"-----BEGIN PRIVATE KEY----- {REDACTED} -----END PRIVATE KEY-----", text)
    masked = _ASSIGNMENT.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{REDACTED}{m.group(3)}", masked)
    masked = _URL_CREDENTIALS.sub(lambda m: f"{m.group(1)}{REDACTED}{m.group(3)}", masked)
    for pattern in _KNOWN:
        masked = pattern.sub(REDACTED, masked)
    return masked


def mask_value(value: Any) -> Any:
    if isinstance(value, str):
        return mask_text(value)
    if isinstance(value, list):
        return [mask_value(v) for v in value]
    if isinstance(value, dict):
        return {k: mask_value(v) for k, v in value.items()}
    return value


def mask_finding_payload(finding) -> None:
    from . import config

    if not config.MASK_SECRETS:
        return
    finding.function_source = mask_text(finding.function_source)
    for evidence in finding.evidence:
        evidence.snippet = mask_text(evidence.snippet)
    for node in finding.ast_nodes:
        node.snippet = mask_text(node.snippet)
    for patch in finding.patch_candidates:
        patch.source = mask_text(patch.source)
        patch.unified_diff = mask_text(patch.unified_diff)
    if finding.explanation:
        finding.explanation = mask_value(finding.explanation)


def mask_scan(scan) -> None:
    for finding in scan.findings:
        mask_finding_payload(finding)
