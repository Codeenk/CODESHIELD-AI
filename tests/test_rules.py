from codeshield.core import rules
from codeshield.models import Engine


def test_detects_sql_injection(vulnerable_snippet):
    findings = rules.scan_text("app.py", vulnerable_snippet)
    cwes = {f.cwe for f in findings}
    assert "CWE-89" in cwes
    finding = next(f for f in findings if f.cwe == "CWE-89")
    assert finding.engine is Engine.rules
    assert finding.location.start_line == 6
    assert finding.fingerprint


def test_detects_command_injection():
    code = "import os\n\ndef ping(h):\n    return os.system('ping ' + h)\n"
    findings = rules.scan_text("cmd.py", code)
    assert any(f.cwe == "CWE-78" for f in findings)


def test_detects_xss_and_eval_js():
    code = "function r(u){ document.getElementById('x').innerHTML = u; }\n"
    findings = rules.scan_text("app.js", code)
    assert any(f.cwe == "CWE-79" for f in findings)


def test_masks_hardcoded_secret():
    code = 'API_KEY = "sk-live-verysecretvalue123"\n'
    findings = rules.scan_text("conf.py", code)
    secret = next(f for f in findings if f.cwe == "CWE-798")
    assert "verysecretvalue123" not in secret.snippet
    assert "********" in secret.snippet


def test_unsupported_language_returns_nothing():
    assert rules.scan_text("notes.txt", "SELECT * FROM x") == []


def test_no_false_positive_on_clean_code():
    code = "def add(a, b):\n    return a + b\n"
    assert rules.scan_text("clean.py", code) == []
