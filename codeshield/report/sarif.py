"""SARIF 2.1.0 output (PRD §7.6 FR-29, CI integration FR-32).

GitHub code scanning and most CI dashboards consume SARIF, so findings map cleanly onto it.
"""

from __future__ import annotations

import json
from typing import Any

from ..models import Engine, ScanResult, Severity

_SARIF_LEVEL = {
    Severity.critical: "error",
    Severity.high: "error",
    Severity.medium: "warning",
    Severity.low: "note",
    Severity.info: "note",
}


def to_sarif(scan: ScanResult) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in scan.findings:
        rule_id = finding.cwe
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": finding.cwe_name or rule_id,
                "shortDescription": {"text": finding.cwe_name or rule_id},
                "fullDescription": {"text": _description(finding)},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{rule_id.split('-')[-1]}.html",
                "properties": {
                    "security-severity": _security_severity(finding.severity),
                    "tags": ["security", finding.owasp or "security"],
                },
            }

        message = f"{finding.title}. {finding.rationale}"
        if finding.engine == Engine.both:
            message = f"[model+rules agree] {message}"

        results.append(
            {
                "ruleId": rule_id,
                "level": _SARIF_LEVEL[finding.severity],
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file},
                            "region": {
                                "startLine": finding.location.start_line,
                                "endLine": finding.location.end_line,
                            },
                        }
                    }
                ],
                "partialFingerprints": {"codeshield/v1": finding.fingerprint or finding.id},
                "properties": {
                    "confidence": finding.confidence,
                    "engine": finding.engine.value,
                    "severity": finding.severity.value,
                },
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeShield AI",
                        "informationUri": "https://github.com/",
                        "version": scan.codeshield_version,
                        "semanticVersion": scan.codeshield_version,
                        "rules": list(rules.values()),
                        "properties": {
                            "modelVersion": scan.model_version or "rules-only",
                            "scanId": scan.id,
                        },
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": scan.status.value == "done",
                        "properties": {"source": scan.source},
                    }
                ],
            }
        ],
    }


def to_sarif_str(scan: ScanResult, indent: int = 2) -> str:
    return json.dumps(to_sarif(scan), indent=indent)


def _security_severity(severity: Severity) -> str:
    return {
        Severity.critical: "9.5",
        Severity.high: "8.0",
        Severity.medium: "5.5",
        Severity.low: "3.0",
        Severity.info: "1.0",
    }[severity]


def _description(finding) -> str:
    parts = [finding.rationale]
    if finding.remediation:
        parts.append(f"Remediation: {finding.remediation}")
    if finding.exploit:
        parts.append(f"Example: {finding.exploit}")
    return " ".join(parts)
