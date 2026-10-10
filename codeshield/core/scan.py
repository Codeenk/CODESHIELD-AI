"""The scan orchestrator (PRD §10).

    ingest -> parse -> detect -> explain -> repair -> verify

Runs per file, tolerates per-file failures (partial results, FR-9 reliability), applies a
project's false-positive fingerprints (FR-14), and only surfaces a patch that has been through
``verify.py``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from ..config import Settings, get_settings
from ..models import (
    FileReport,
    Finding,
    PatchStatus,
    ScanConfig,
    ScanResult,
    ScanStatus,
    ScanSummary,
    Severity,
    utc_now,
)
from .detection import DetectionService
from .explainability import explain_all
from .ingestion import IngestedFile
from .parsing import analyze_file
from .repair import generate_candidates, redact
from .verify import verify_and_finalize

_STATUS_RANK = {
    PatchStatus.verified: 2,
    PatchStatus.partial: 1,
    PatchStatus.unverified: 0,
}

ProgressCallback = Callable[[int, int, str], None]


@dataclass
class ScanOptions:
    settings: Settings = field(default_factory=get_settings)
    suppress_fingerprints: set[str] = field(default_factory=set)
    run_tests: bool = False


class Scanner:
    def __init__(self, options: ScanOptions | None = None) -> None:
        self.options = options or ScanOptions()
        self.detection = DetectionService(self.options.settings)

    # ------------------------------------------------------------------ #
    def scan(
        self,
        files: Iterable[IngestedFile],
        source: str,
        progress: ProgressCallback | None = None,
    ) -> ScanResult:
        settings = self.options.settings
        result = ScanResult(
            status=ScanStatus.running,
            source=source,
            config=ScanConfig(
                languages=list(settings.supported_languages),
                model_threshold=settings.model_threshold,
                model_enabled=not settings.disable_model,
                retain_code=settings.retain_code,
            ),
        )

        file_list = list(files)
        total = len(file_list)
        for index, ingested in enumerate(file_list, start=1):
            if progress:
                progress(index, total, ingested.path)
            self._scan_one(ingested, result)

        self._finalize(result)
        return result

    # ------------------------------------------------------------------ #
    def _scan_one(self, ingested: IngestedFile, result: ScanResult) -> None:
        if ingested.skipped:
            result.files.append(
                FileReport(
                    path=ingested.path,
                    language=ingested.language,
                    loc=0,
                    sha256=ingested.sha256,
                    skipped=True,
                    skip_reason=ingested.skip_reason,
                )
            )
            return

        try:
            analysis = analyze_file(ingested.path, ingested.text, ingested.language)
            outcome = self.detection.detect(analysis)
            findings = explain_all(outcome.findings, analysis)
        except Exception as exc:  # partial results, never a whole-scan crash
            result.files.append(
                FileReport(
                    path=ingested.path,
                    language=ingested.language,
                    loc=ingested.text.count("\n") + 1,
                    sha256=ingested.sha256,
                    skipped=True,
                    skip_reason=f"scan error: {exc.__class__.__name__}: {exc}",
                )
            )
            return

        fresh: list[Finding] = []
        for finding in findings:
            if finding.fingerprint and finding.fingerprint in self.options.suppress_fingerprints:
                continue  # known false positive for this project (FR-14)
            fresh.append(finding)

        result.findings.extend(fresh)
        result.engine_notes.extend(outcome.notes)
        if outcome.model_version:
            result.model_version = outcome.model_version

        self._repair(analysis, fresh, result)

        result.files.append(
            FileReport(
                path=ingested.path,
                language=ingested.language,
                loc=analysis.loc,
                sha256=ingested.sha256,
                findings=len(fresh),
            )
        )

    def _repair(self, analysis, findings: list[Finding], result: ScanResult) -> None:
        for finding in findings:
            candidates = generate_candidates(finding, analysis, self.options.settings)
            if not candidates:
                continue
            verified = [
                (c, verify_and_finalize(c, finding, analysis, self.options.settings, self.options.run_tests))
                for c in candidates
            ]
            verified.sort(key=lambda pair: (-_STATUS_RANK[pair[1].status], pair[1].rank))
            best_patch = verified[0][1]
            # Never let a leaked credential reach the UI, a report or an artefact (§9).
            best_patch.original_code = redact(best_patch.original_code)
            best_patch.patched_code = redact(best_patch.patched_code)
            best_patch.diff = redact(best_patch.diff)
            if len(verified) > 1:
                best_patch.verification.append(
                    f"{len(verified)} candidate patches generated; showing the best."
                )
            result.patches.append(best_patch)

    # ------------------------------------------------------------------ #
    def _finalize(self, result: ScanResult) -> None:
        result.findings.sort(key=lambda f: f.sort_key())
        result.engine_notes = list(dict.fromkeys(result.engine_notes))
        result.finished_at = utc_now()
        result.status = ScanStatus.done

        by_severity = {sev.value: 0 for sev in Severity}
        by_cwe: dict[str, int] = {}
        for finding in result.findings:
            by_severity[finding.severity.value] = by_severity.get(finding.severity.value, 0) + 1
            by_cwe[finding.cwe] = by_cwe.get(finding.cwe, 0) + 1

        result.summary = ScanSummary(
            files_scanned=sum(1 for f in result.files if not f.skipped),
            files_skipped=sum(1 for f in result.files if f.skipped),
            total_findings=len(result.findings),
            by_severity=by_severity,
            by_cwe=dict(sorted(by_cwe.items(), key=lambda kv: -kv[1])),
            patches_verified=sum(1 for p in result.patches if p.status == PatchStatus.verified),
        )


# --------------------------------------------------------------------------- #
# Convenience entry points
# --------------------------------------------------------------------------- #


def scan_ingested(
    files: Iterable[IngestedFile], source: str, options: ScanOptions | None = None
) -> ScanResult:
    return Scanner(options).scan(files, source)


def scan_text(
    text: str,
    path: str = "inline.py",
    source: str = "inline",
    options: ScanOptions | None = None,
) -> ScanResult:
    """Scan an in-memory snippet (used by the CLI and the test-suite)."""
    from .ingestion import IngestedFile
    from .parsing import detect_language, sha256_text

    language = detect_language(path)
    if language is None:
        ingested = IngestedFile(
            path, "", "text", len(text), sha256_text(text), True, "unsupported file type"
        )
    else:
        ingested = IngestedFile(path, text, language, len(text), sha256_text(text))
    return scan_ingested([ingested], source, options)
