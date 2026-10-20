"""Scan orchestration: ingest, parse, detect, explain, repair, finalize."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Callable, Optional

from . import config, store
from .detection.engine import build_findings, catalog
from .detection.rules import detect_unit
from .explain.explainer import explain_finding
from .ingestion.loader import (
    IngestionError, Workspace, clone_repo, workspace_from_snippet,
    workspace_from_uploads, workspace_from_zip,
)
from .knowledge.loader import get_knowledge_base
from .parsing.parser import parse_file
from .privacy import mask_finding_payload
from .repair.patcher import apply_retention, build_patches
from .sandbox.runner import TestRunner
from .schemas import CodeUnit, Finding, Scan, ScanSummary


class ScanCancelled(Exception):
    pass


Progress = Optional[Callable[[str, int], None]]
CancelCheck = Optional[Callable[[], bool]]


def _report(progress: Progress, stage: str, value: int) -> None:
    if progress:
        progress(stage, max(0, min(100, value)))


def _cancelled(should_cancel: CancelCheck) -> None:
    if should_cancel and should_cancel():
        raise ScanCancelled("Scan cancelled")


def _ingest(source: dict) -> Workspace:
    kind = source.get("type")
    if kind == "snippet":
        return workspace_from_snippet(source["filename"], source["code"])
    if kind == "upload":
        return workspace_from_uploads(source["files"])
    if kind == "zip":
        return workspace_from_zip(source["filename"], source["data"])
    if kind == "repo":
        return clone_repo(source["url"], source.get("branch"), source.get("commit"))
    raise IngestionError("Unsupported scan source")


def _coverage(units: list[CodeUnit]) -> dict:
    kb = get_knowledge_base()
    entries = catalog()
    rule_slugs = {entry["slug"] for entry in entries}
    modules = kb.vulnerabilities
    not_covered = sorted(slug for slug in modules if slug not in rule_slugs)
    return {
        "rules": len(entries),
        "knowledge_modules": len(modules),
        "owasp": sorted({entry["owasp"] for entry in entries if entry.get("owasp")}),
        "languages": sorted({unit.language for unit in units}),
        "not_statically_covered": not_covered,
        "limitations": [
            "Business logic, authorization, and race conditions need manual review.",
            "Rule findings are review candidates, not proof of exploitability.",
            "Repairs are verified against available tests only when test execution is enabled.",
            "Dependencies, infrastructure configuration, and generated code are out of scope.",
        ],
    }


def _summary(
    scan: Scan, findings: list[Finding], files: int, units: int, lines: int,
    engine_notes: list[str], errors: list[dict[str, str]], coverage: dict,
    model_used: bool, model_id: str, duration_ms: int,
) -> ScanSummary:
    active = [finding for finding in findings if not finding.suppressed]
    by_severity = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    by_cwe: dict[str, int] = {}
    by_engine: dict[str, int] = {}
    by_file: dict[str, int] = {}
    for finding in active:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_cwe[finding.cwe] = by_cwe.get(finding.cwe, 0) + 1
        by_engine[finding.engine] = by_engine.get(finding.engine, 0) + 1
        by_file[finding.path] = by_file.get(finding.path, 0) + 1
    return ScanSummary(
        total_findings=len(active), by_severity=by_severity, by_cwe=by_cwe,
        by_engine=by_engine, by_file=by_file, files_scanned=files, units_scanned=units,
        lines_scanned=lines, languages=coverage.get("languages", []),
        model_used=model_used, model_id=model_id if model_used else "",
        engine_notes=engine_notes, errors=errors[:50],
        suppressed=len(findings) - len(active), coverage=coverage, duration_ms=duration_ms,
    )


def _basic_explanation(finding: Finding) -> dict:
    return {
        "summary": f"{finding.cwe_title} in {finding.function} at {finding.path}:{finding.start_line}.",
        "why": finding.message,
        "attack": "Untrusted data can reach a dangerous operation without an effective control.",
        "remediation": ["Validate untrusted input and apply the linked security control."],
        "references": [],
        "evidence": [item.model_dump() for item in finding.evidence],
        "attribution": {"method": "rules", "lines": []},
    }


def run_scan(
    scan: Scan, source: dict, progress: Progress = None, should_cancel: CancelCheck = None,
) -> Scan:
    started = time.monotonic()
    scan.started_at = datetime.now(timezone.utc)
    scan.status = "running"
    scan.stage = "ingesting"
    _report(progress, "ingesting", 3)
    _cancelled(should_cancel)
    workspace = _ingest(source)
    try:
        scan.target = workspace.target
        scan.source_type = workspace.source_type
        scan.config["commit"] = workspace.meta.get("commit", "")
        scan.config["branch"] = workspace.meta.get("branch", "")
        if not scan.project_name:
            scan.project_name = workspace.target

        _report(progress, "parsing", 15)
        _cancelled(should_cancel)
        units: list[CodeUnit] = []
        errors: list[dict[str, str]] = []
        lines = 0
        for index, (path, content) in enumerate(sorted(workspace.files.items())):
            lines += content.count("\n") + 1
            try:
                parsed = parse_file(path, content)
                units.extend(parsed.units)
                if parsed.error:
                    errors.append({"path": path, "error": parsed.error[:300]})
            except Exception as exc:
                errors.append({"path": path, "error": f"Parser error: {exc}"[:300]})
            if index % 50 == 0:
                _cancelled(should_cancel)
                _report(progress, "parsing", 15 + int(15 * index / max(1, len(workspace.files))))
        if not units:
            raise IngestionError("No supported source files were found")

        _report(progress, "detecting", 34)
        _cancelled(should_cancel)
        model_mode = (scan.config.get("model_mode") or config.MODEL_MODE or "auto").lower()
        result = build_findings(units, enable_model=model_mode != "off")
        findings = result.findings

        for finding in findings:
            finding.scan_id = scan.id
            finding.project_id = scan.project_id

        suppressed = store.suppression_map(scan.project_id or "") if scan.project_id else {}
        for finding in findings:
            status = suppressed.get(finding.fingerprint)
            if status:
                finding.status = status
                finding.suppressed = True

        unit_index = {(unit.path, unit.name, unit.start_line): unit for unit in units}

        _report(progress, "explaining", 50)
        attention_budget = config.ATTENTION_FINDING_LIMIT if result.model_used else 0
        active = [finding for finding in findings if not finding.suppressed]
        for index, finding in enumerate(active):
            _cancelled(should_cancel)
            unit = unit_index.get((finding.path, finding.function, finding.start_line))
            try:
                finding.explanation = explain_finding(
                    finding, unit, enable_model=index < attention_budget
                )
            except Exception as exc:
                finding.explanation = _basic_explanation(finding)
                result.notes.append(f"Explanation fallback for {finding.path}:{finding.start_line}: {exc}")
            if index % 10 == 0:
                _report(progress, "explaining", 50 + int(10 * index / max(1, len(active))))

        patch_notes: list[str] = []
        generate_patches = bool(scan.config.get("generate_patches", True))
        if generate_patches and active:
            _report(progress, "repairing", 62)
            runner: Optional[TestRunner] = None
            if workspace.source_type in {"repo", "zip"}:
                runner = TestRunner(workspace.root, workspace.files)
            budget = active[: config.MAX_PATCH_FINDINGS]
            if len(active) > len(budget):
                patch_notes.append(
                    f"Repair generation capped at {len(budget)} findings; review the rest manually"
                )
            for index, finding in enumerate(budget):
                _cancelled(should_cancel)
                unit = unit_index.get((finding.path, finding.function, finding.start_line))
                if unit is None:
                    continue
                try:
                    original_hits = detect_unit(unit)
                    finding.patch_candidates = build_patches(
                        finding, unit, original_hits, runner,
                        allow_llm=config.REPAIR_PROVIDER != "none",
                    )
                    for candidate in finding.patch_candidates:
                        apply_retention(candidate)
                except Exception as exc:
                    patch_notes.append(f"Repair failed for {finding.path}:{finding.start_line}: {exc}"[:240])
                if index % 5 == 0:
                    _report(progress, "repairing", 62 + int(18 * index / max(1, len(budget))))
            if not config.RUN_TESTS and runner and runner.has_tests:
                patch_notes.append(
                    "Tests were found but not executed; enable CODESHIELD_RUN_TESTS to verify patches dynamically"
                )
            if config.REPAIR_PROVIDER == "none":
                patch_notes.append("LLM repair is disabled; deterministic templates only")

        _report(progress, "finalizing", 86)
        _cancelled(should_cancel)
        if not config.RETAIN_CODE:
            for finding in findings:
                finding.function_source = ""
        for finding in findings:
            mask_finding_payload(finding)

        coverage = _coverage(units)
        duration_ms = int((time.monotonic() - started) * 1000)
        notes = list(result.notes)
        if config.RETAIN_CODE:
            notes.append("Full function source retained in this scan (CODESHIELD_RETAIN_CODE=true)")
        else:
            notes.append("Function bodies are not retained; evidence snippets and patch diffs are kept")
        notes.extend(patch_notes)
        if scan.config.get("branch") or scan.config.get("commit"):
            notes.append(
                f"Revision: {scan.config.get('branch') or 'default'} @ "
                f"{(scan.config.get('commit') or '')[:12]}"
            )

        scan.summary = _summary(
            scan, findings, len(workspace.files), len(units), lines, notes, errors,
            coverage, result.model_used, result.model_id, duration_ms,
        )
        scan.findings = findings
        scan.status = "completed"
        scan.stage = "completed"
        scan.progress = 100
        scan.finished_at = datetime.now(timezone.utc)
        _report(progress, "completed", 100)
        return scan
    finally:
        workspace.cleanup()
