from codeshield.core.ingestion import ingest_directory
from codeshield.core.scan import Scanner, ScanOptions, scan_text
from codeshield.models import PatchStatus, ScanStatus


def test_scan_examples_end_to_end(examples_dir):
    files = ingest_directory(str(examples_dir))
    scan = Scanner().scan(files, source="examples/vulnerable")

    assert scan.status is ScanStatus.done
    assert scan.summary.files_scanned >= 5
    assert scan.summary.total_findings >= 8

    cwes = {f.cwe for f in scan.findings}
    for expected in {"CWE-89", "CWE-78", "CWE-79", "CWE-798"}:
        assert expected in cwes, f"expected {expected} in {cwes}"


def test_every_finding_is_explained(examples_dir):
    scan = Scanner().scan(ingest_directory(str(examples_dir)), source="examples")
    for finding in scan.findings:
        assert finding.rationale
        assert finding.syntax_nodes
        assert finding.attention
        assert finding.cwe.startswith("CWE-")


def test_findings_produce_verified_patches(examples_dir):
    scan = Scanner().scan(ingest_directory(str(examples_dir)), source="examples")
    assert scan.patches, "expected at least one patch"
    assert any(p.status is PatchStatus.verified for p in scan.patches)
    for patch in scan.patches:
        assert patch.verification, "patches must record their checks"


def test_secrets_are_masked_in_results(examples_dir):
    scan = Scanner().scan(ingest_directory(str(examples_dir)), source="examples")
    blob = scan.model_dump_json()
    assert "SuperSecret123!" not in blob
    assert "sk-live-9f2c7a41deadbeef001122334455" not in blob


def test_suppressed_fingerprint_is_removed():
    code = "import os\n\ndef ping(h):\n    return os.system('ping ' + h)\n"
    base = scan_text(code, "cmd.py")
    assert base.findings
    fingerprint = base.findings[0].fingerprint
    options = ScanOptions(suppress_fingerprints={fingerprint})
    suppressed = Scanner(options).scan(
        ingest_text(code, "cmd.py"), source="inline"
    )
    assert all(f.fingerprint != fingerprint for f in suppressed.findings)


def test_clean_code_yields_no_findings():
    code = "def add(a, b):\n    return a + b\n"
    result = scan_text(code, "clean.py")
    assert result.summary.total_findings == 0


def ingest_text(code: str, path: str):
    from codeshield.core.ingestion import IngestedFile
    from codeshield.core.parsing import sha256_text

    return [IngestedFile(path, code, "python", len(code), sha256_text(code))]
