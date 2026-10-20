from conftest import PY_VULN

from codeshield.reporting import reporter


def test_sarif_shape(scan_snippet):
    scan = scan_snippet(PY_VULN)
    sarif = reporter.build_sarif(scan)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "CodeShield AI"
    assert run["results"]
    region = run["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] >= 1


def test_html_contains_cwe_and_escapes(scan_snippet):
    html = reporter.build_html(scan_snippet(PY_VULN))
    assert "CodeShield AI" in html
    assert "CWE-" in html
    assert "<script>alert" not in html


def test_pdf_is_valid_header(scan_snippet):
    pdf = reporter.build_pdf(scan_snippet(PY_VULN))
    assert pdf[:4] == b"%PDF"


def test_json_roundtrip(scan_snippet):
    scan = scan_snippet(PY_VULN)
    text = reporter.build_json(scan)
    assert scan.id in text
    assert "CWE-" in text
