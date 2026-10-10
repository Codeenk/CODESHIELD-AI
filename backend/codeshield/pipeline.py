"""End-to-end scan orchestration."""
from __future__ import annotations

import logging
import shutil
import uuid
from pathlib import Path
from typing import Optional

from . import __version__, config
from .detection.engine import DetectionEngine
from .explain.explainer import ExplainEngine
from .ingestion.loader import SourceFile, collect_from_directory, collect_from_uploads, clone_repo
from .knowledge.loader import get_knowledge_base
from .parsing.parser import parse_file
from .repair.patcher import PatchGenerator
from .schemas import Finding, Scan, ScanSummary
from .store.store import Store

log = logging.getLogger("codeshield.pipeline")


class CodeShieldPipeline:
    def __init__(
        self,
        store: Optional[Store] = None,
        engine: Optional[DetectionEngine] = None,
        explainer: Optional[ExplainEngine] = None,
        patcher: Optional[PatchGenerator] = None,
    ) -> None:
        self.kb = get_knowledge_base()
        self.store = store if store is not None else Store()
        self.engine = engine or DetectionEngine(kb=self.kb)
        self.explainer = explainer or ExplainEngine(kb=self.kb)
        self.patcher = patcher or PatchGenerator()

    # -- public entry points ----------------------------------------------
    def scan_paths(self, path: Path, target: Optional[str] = None, generate_patches: bool = True) -> Scan:
        files = collect_from_directory(Path(path))
        return self.scan_files(files, target=target or str(path), source_type="upload",
                               generate_patches=generate_patches)

    def scan_files(
        self,
        files: list[SourceFile],
        target: str,
        source_type: str = "upload",
        generate_patches: bool = True,
    ) -> Scan:
        scan = Scan(
            id=uuid.uuid4().hex[:12],
            target=target,
            source_type=source_type,  # type: ignore[arg-type]
            status="running",
            config={
                "codeshield_version": __version__,
                "model_id": config.DETECTION_MODEL_ID,
                "model_mode": config.MODEL_MODE,
                "kb_vulnerabilities": len(self.kb.vulnerabilities),
                "generate_patches": generate_patches,
            },
        )
        suppressed = self.store.suppressed_fingerprints()
        findings: list[Finding] = []
        units_scanned = 0
        languages: set[str] = set()

        for source in files:
            languages.add(source.language)
            parsed = parse_file(source.path, source.text, source.language)
            for unit in parsed.units:
                units_scanned += 1
                for finding in self.engine.detect_unit(unit):
                    if finding.fingerprint in suppressed:
                        continue
                    finding.scan_id = scan.id
                    finding.explanation = self.explainer.explain(finding, unit)
                    if generate_patches:
                        finding.patch_candidates = self.patcher.generate(finding, unit)
                    findings.append(finding)

        scan.findings = findings
        scan.summary = self._summarize(findings, files, units_scanned, languages)
        scan.status = "completed"
        try:
            self.store.save_scan(scan)
        except Exception as exc:  # noqa: BLE001
            log.warning("Failed to persist scan %s: %s", scan.id, exc)
        return scan

    def scan_uploads(self, uploads: list[tuple[str, bytes]], target: str = "upload") -> Scan:
        files = collect_from_uploads(uploads)
        return self.scan_files(files, target=target, source_type="upload")

    def scan_repo(self, url: str, branch: Optional[str] = None, generate_patches: bool = True) -> Scan:
        path = clone_repo(url, branch)
        try:
            files = collect_from_directory(path)
            return self.scan_files(files, target=url, source_type="repo",
                                   generate_patches=generate_patches)
        finally:
            shutil.rmtree(path, ignore_errors=True)

    # -- helpers -----------------------------------------------------------
    def _summarize(
        self,
        findings: list[Finding],
        files: list[SourceFile],
        units_scanned: int,
        languages: set[str],
    ) -> ScanSummary:
        by_severity: dict[str, int] = {}
        by_cwe: dict[str, int] = {}
        by_engine: dict[str, int] = {}
        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_cwe[f.cwe] = by_cwe.get(f.cwe, 0) + 1
            by_engine[f.engine] = by_engine.get(f.engine, 0) + 1
        return ScanSummary(
            total_findings=len(findings),
            by_severity=by_severity,
            by_cwe=by_cwe,
            by_engine=by_engine,
            files_scanned=len(files),
            units_scanned=units_scanned,
            languages=sorted(languages),
            model_used=bool(getattr(self.engine.detector, "available", False)),
            coverage=self.kb.summary(),
        )


_pipeline: Optional[CodeShieldPipeline] = None


def get_pipeline() -> CodeShieldPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = CodeShieldPipeline()
    return _pipeline
