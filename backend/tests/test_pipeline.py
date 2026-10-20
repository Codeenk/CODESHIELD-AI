import pytest
from conftest import PY_VULN, scan_source

from codeshield.pipeline import ScanCancelled, run_scan
from codeshield.schemas import Scan


def test_scan_snippet_end_to_end(scan_snippet):
    scan = scan_snippet(PY_VULN)
    assert scan.status == "completed"
    assert scan.summary.total_findings >= 3
    assert scan.summary.files_scanned == 1
    assert scan.summary.model_used is False
    assert all(f.explanation and f.explanation.get("summary") for f in scan.findings)
    assert all(f.patch_candidates for f in scan.findings)


def test_scan_without_patches():
    scan = scan_source(
        {"type": "snippet", "filename": "a.py", "code": "import pickle\ndef f(d):\n    return pickle.loads(d)\n"},
        patches=False,
    )
    assert scan.findings
    assert all(f.patch_candidates == [] for f in scan.findings)


def test_function_source_not_retained(scan_snippet):
    scan = scan_snippet(PY_VULN)
    assert all(f.function_source == "" for f in scan.findings)
    assert all(f.evidence for f in scan.findings)


def test_summary_breakdowns_are_consistent(scan_snippet):
    summary = scan_snippet(PY_VULN).summary
    assert sum(summary.by_severity.values()) == summary.total_findings
    assert sum(summary.by_cwe.values()) == summary.total_findings
    assert sum(summary.by_file.values()) == summary.total_findings
    assert summary.coverage["rules"] >= 1
    assert "limitations" in summary.coverage


def test_cancel_callback_stops_scan():
    scan = Scan(id="cancel-me", target="sample", source_type="snippet")
    with pytest.raises(ScanCancelled):
        run_scan(
            scan,
            {"type": "snippet", "filename": "a.py", "code": PY_VULN},
            should_cancel=lambda: True,
        )
    assert scan.status == "running"


def test_progress_callback_reaches_finalizing():
    stages = []
    scan = Scan(id="progress", target="sample", source_type="snippet")
    run_scan(
        scan,
        {"type": "snippet", "filename": "a.py", "code": PY_VULN},
        progress=lambda stage, value: stages.append((stage, value)),
    )
    assert stages[-1][0] == "completed"
    assert stages[-1][1] == 100


def test_empty_source_is_rejected():
    from codeshield.ingestion.loader import IngestionError

    scan = Scan(id="empty", target="sample", source_type="snippet")
    with pytest.raises(IngestionError):
        run_scan(scan, {"type": "snippet", "filename": "a.txt", "code": "hello"})
