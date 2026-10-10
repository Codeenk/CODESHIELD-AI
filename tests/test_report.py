import json

from codeshield.core.scan import scan_text
from codeshield.report import to_json, to_pdf, to_sarif, to_sarif_str

VULN = "import os\n\ndef ping(h):\n    return os.system('ping ' + h)\n"


def _scan():
    return scan_text(VULN, "cmd.py")


def test_json_report_round_trips():
    scan = _scan()
    payload = json.loads(to_json(scan))
    assert payload["id"] == scan.id
    assert payload["summary"]["total_findings"] == len(scan.findings)


def test_sarif_structure_and_rules():
    scan = _scan()
    sarif = to_sarif(scan)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "CodeShield AI"
    assert run["results"]
    result = run["results"][0]
    assert result["ruleId"] == "CWE-78"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 4


def test_sarif_is_valid_json_string():
    assert json.loads(to_sarif_str(_scan()))["version"] == "2.1.0"


def test_pdf_is_a_pdf_document():
    data = to_pdf(_scan())
    assert data.startswith(b"%PDF-")
    assert data.rstrip().endswith(b"%%EOF")
    # xref + trailer are present for a well-formed file
    assert b"/Type /Catalog" in data
    assert b"startxref" in data
