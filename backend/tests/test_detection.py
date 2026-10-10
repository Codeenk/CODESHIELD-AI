from codeshield.detection.engine import DetectionEngine
from codeshield.detection.model import NullDetector
from codeshield.detection.rules import RuleEngine
from codeshield.parsing.parser import parse_file


def engine():
    return DetectionEngine(detector=NullDetector())


def test_sql_injection_detected():
    unit = parse_file("a.py", 'def f(q):\n    cur.execute("SELECT * FROM t WHERE id = " + q)',
                      "python").units[0]
    findings = engine().detect_unit(unit)
    assert any(f.cwe == "CWE-89" for f in findings)


def test_parameterized_query_not_flagged():
    unit = parse_file("a.py", 'def f(q):\n    cur.execute("SELECT * FROM t WHERE id = ?", (q,))',
                      "python").units[0]
    assert engine().detect_unit(unit) == []


def test_pickle_is_high_severity_deserialization():
    unit = parse_file("a.py", "def f(d):\n    return pickle.loads(d)", "python").units[0]
    findings = engine().detect_unit(unit)
    assert any(f.cwe == "CWE-502" and f.severity == "high" for f in findings)


def test_javascript_xss_detected():
    unit = parse_file("a.js", "const r = (n) => { el.innerHTML = n; };", "javascript").units[0]
    findings = engine().detect_unit(unit)
    assert any(f.cwe == "CWE-79" for f in findings)


def test_weak_hash_has_no_knowledge_ref():
    unit = parse_file("a.py", "def f(p):\n    return hashlib.md5(p)", "python").units[0]
    findings = engine().detect_unit(unit)
    weak = [f for f in findings if f.cwe == "CWE-328"]
    assert weak and weak[0].knowledge_ref is None


def test_confidence_is_clamped_and_engine_tagged():
    unit = parse_file("a.py", "def f(d):\n    return pickle.loads(d)", "python").units[0]
    finding = engine().detect_unit(unit)[0]
    assert 0.0 <= finding.confidence <= 1.0
    assert finding.engine == "rules"


def test_fingerprint_stable_across_runs():
    src = "def f(d):\n    return pickle.loads(d)"
    a = parse_file("a.py", src, "python").units[0]
    b = parse_file("a.py", src, "python").units[0]
    fa = engine().detect_unit(a)[0].fingerprint
    fb = engine().detect_unit(b)[0].fingerprint
    assert fa == fb


class _AlwaysInsecureDetector:
    """Stands in for the reference checkpoint, which flags most code as risky."""

    enabled = True
    available = True

    def predict_proba(self, texts):
        return [0.99 for _ in texts]


def test_model_alone_does_not_raise_findings_by_default():
    # Precision guard: a clean function must not become a finding just because
    # the binary model is unsure. Model-only findings are opt-in.
    unit = parse_file("a.py", "def f(x):\n    return x + 1", "python").units[0]
    eng = DetectionEngine(detector=_AlwaysInsecureDetector())
    assert eng.detect_unit(unit) == []


def test_model_only_findings_when_opted_in(monkeypatch):
    from codeshield import config

    monkeypatch.setattr(config, "MODEL_ONLY", True)
    unit = parse_file("a.py", "def f(x):\n    return x + 1", "python").units[0]
    eng = DetectionEngine(detector=_AlwaysInsecureDetector())
    findings = eng.detect_unit(unit)
    assert len(findings) == 1 and findings[0].engine == "model"


def test_model_agreement_boosts_rule_finding():
    unit = parse_file("a.py", "def f(d):\n    return pickle.loads(d)", "python").units[0]
    eng = DetectionEngine(detector=_AlwaysInsecureDetector())
    finding = eng.detect_unit(unit)[0]
    assert finding.engine == "both"
    assert finding.confidence > 0.75
