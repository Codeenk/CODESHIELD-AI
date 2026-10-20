from conftest import JS_VULN, PY_VULN, detect, make_unit

from codeshield.detection.engine import build_findings
from codeshield.parsing.parser import parse_file


def test_sql_injection_detected():
    found = detect('def f(q):\n    cur.execute("SELECT * FROM t WHERE id = " + q)')
    assert any(f.cwe == "CWE-89" for f in found)


def test_parameterized_query_not_flagged():
    assert detect('def f(q):\n    cur.execute("SELECT * FROM t WHERE id = ?", (q,))') == []


def test_pickle_is_high_severity_deserialization():
    found = detect("def f(d):\n    return pickle.loads(d)")
    assert any(f.cwe == "CWE-502" and f.severity == "high" for f in found)


def test_javascript_xss_detected():
    found = detect("const r = (n) => { el.innerHTML = n; };", "a.js")
    assert any(f.cwe == "CWE-79" for f in found)


def test_weak_hash_maps_to_knowledge_module():
    found = [f for f in detect("def f(p):\n    return hashlib.md5(p)") if f.cwe == "CWE-328"]
    assert found and found[0].knowledge_ref == "weak_cryptography"


def test_confidence_is_clamped_and_engine_tagged():
    finding = detect("def f(d):\n    return pickle.loads(d)")[0]
    assert 0.0 <= finding.confidence <= 1.0
    assert finding.engine == "rules"


def test_fingerprint_stable_across_runs():
    src = "def f(d):\n    return pickle.loads(d)"
    first = detect(src)[0].fingerprint
    second = detect(src)[0].fingerprint
    assert first and first == second


def test_vulnerable_sample_is_fully_detected():
    parsed = parse_file("samples/vulnerable/app.py", PY_VULN)
    assert parsed.units
    found = build_findings(parsed.units, enable_model=False).findings
    assert {"CWE-89", "CWE-78", "CWE-502"} <= {f.cwe for f in found}


def test_javascript_sample_detects_sql_and_xss():
    parsed = parse_file("samples.js", JS_VULN)
    found = build_findings(parsed.units, enable_model=False).findings
    assert {"CWE-89", "CWE-79"} <= {f.cwe for f in found}


def test_guarded_path_traversal_is_not_flagged():
    src = (
        "import os\n"
        "def read(secure_filename, base='/var/reports'):\n"
        "    path = os.path.abspath(os.path.join(base, secure_filename))\n"
        "    if not path.startswith(os.path.abspath(base)):\n"
        "        raise ValueError('path traversal')\n"
        "    with open(path) as handle:\n"
        "        return handle.read()\n"
    )
    assert detect(src) == []


def test_resolve_parents_guard_is_not_flagged():
    src = (
        "from pathlib import Path\n"
        "def read(name, root='.'):\n"
        "    candidate = (Path(root) / name).resolve()\n"
        "    if Path(root).resolve() not in candidate.parents:\n"
        "        raise ValueError('escape')\n"
        "    return candidate.read_text()\n"
    )
    assert detect(src) == []


def test_regex_guard_is_not_flagged():
    src = (
        "import re\n"
        "def item(slug):\n"
        "    if not re.fullmatch(r'[a-z0-9_]{1,80}', slug):\n"
        "        raise ValueError('bad slug')\n"
        "    return open('/srv/kb/' + slug + '.md').read()\n"
    )
    assert detect(src) == []


def test_argparse_result_is_not_tainted():
    src = (
        "import argparse\n"
        "def main():\n"
        "    parser = argparse.ArgumentParser()\n"
        "    parser.add_argument('path')\n"
        "    args = parser.parse_args()\n"
        "    return open(args.path).read()\n"
    )
    assert detect(src) == []


def test_vulnerable_string_inside_test_is_not_flagged():
    src = (
        "def test_detection():\n"
        "    sample = 'cur.execute(\"SELECT * FROM t WHERE id = \" + q)'\n"
        "    assert sample\n"
    )
    assert detect(src) == []


def test_same_cwe_on_one_line_is_deduplicated():
    src = "def f(q):\n    cur.execute('SELECT * FROM t WHERE id = ' + q); cur.execute('SELECT 1' + q)\n"
    found = [f for f in detect(src) if f.cwe == "CWE-89"]
    assert len(found) == 1


def test_clean_sample_has_no_findings():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2] / "samples" / "clean"
    units = []
    for path in root.glob("*.py"):
        units.extend(parse_file(str(path), path.read_text(encoding="utf-8")).units)
    assert units and build_findings(units, enable_model=False).findings == []


def test_backend_self_scan_has_no_false_positives():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "codeshield"
    units = []
    for path in root.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        parsed = parse_file(str(path), path.read_text(encoding="utf-8"))
        units.extend(parsed.units)
    assert len(units) > 200
    result = build_findings(units, enable_model=False)
    assert result.findings == [], [
        (f.cwe, f.path, f.evidence[0].line if f.evidence else f.start_line)
        for f in result.findings
    ]
