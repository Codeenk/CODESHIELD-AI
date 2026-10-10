from conftest import PY_VULN

from codeshield.pipeline import CodeShieldPipeline


def test_scan_uploads_end_to_end():
    pipeline = CodeShieldPipeline()
    scan = pipeline.scan_uploads([("app.py", PY_VULN.encode("utf-8"))], target="app.py")
    assert scan.status == "completed"
    assert scan.summary.total_findings >= 3
    assert scan.summary.files_scanned == 1
    assert scan.summary.model_used is False
    assert all(f.explanation for f in scan.findings)
    assert all(f.patch_candidates for f in scan.findings)


def test_scan_reloads_from_store():
    pipeline = CodeShieldPipeline()
    scan = pipeline.scan_uploads([("app.py", PY_VULN.encode("utf-8"))])
    loaded = pipeline.store.get_scan(scan.id)
    assert loaded is not None
    assert loaded.summary.total_findings == scan.summary.total_findings
    assert {f.id for f in loaded.findings} == {f.id for f in scan.findings}


def test_false_positive_suppression_on_rescan():
    pipeline = CodeShieldPipeline()
    scan = pipeline.scan_uploads([("app.py", PY_VULN.encode("utf-8"))])
    target = scan.findings[0]
    pipeline.store.update_finding_status(target.id, "false_positive")

    rescan = pipeline.scan_uploads([("app.py", PY_VULN.encode("utf-8"))])
    assert all(f.fingerprint != target.fingerprint for f in rescan.findings)


def test_summary_breakdowns_are_consistent():
    pipeline = CodeShieldPipeline()
    scan = pipeline.scan_uploads([("app.py", PY_VULN.encode("utf-8"))])
    s = scan.summary
    assert sum(s.by_severity.values()) == s.total_findings
    assert sum(s.by_cwe.values()) == s.total_findings
    assert s.coverage["vulnerability_count"] == 29
