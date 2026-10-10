from conftest import PY_VULN

from codeshield.pipeline import CodeShieldPipeline
from codeshield.reporting import reporter


def _scan():
    return CodeShieldPipeline().scan_uploads([("app.py", PY_VULN.encode("utf-8"))])


def test_sarif_shape():
    sarif = reporter.to_sarif(_scan())
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "CodeShield AI"
    assert run["results"]
    assert run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_html_contains_cwe_and_escapes():
    html = reporter.to_html(_scan())
    assert "CodeShield AI" in html
    assert "CWE-" in html


def test_pdf_is_valid_header():
    pdf = reporter.to_pdf(_scan())
    assert pdf[:4] == b"%PDF"


def test_json_roundtrip():
    scan = _scan()
    text = reporter.to_json(scan)
    assert scan.id in text
