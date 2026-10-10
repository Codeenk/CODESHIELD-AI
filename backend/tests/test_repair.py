from codeshield.detection.engine import DetectionEngine
from codeshield.detection.model import NullDetector
from codeshield.parsing.parser import parse_file
from codeshield.repair.patcher import PatchGenerator
from codeshield.sandbox.verifier import Verifier


def _finding(src, name="f"):
    unit = parse_file("a.py", src, "python").units[0]
    engine = DetectionEngine(detector=NullDetector())
    return unit, engine.detect_unit(unit)[0]


def test_sql_patch_is_verified_and_removes_finding():
    unit, finding = _finding('def f(q):\n    cur.execute("SELECT * FROM t WHERE id = " + q)')
    candidates = PatchGenerator().generate(finding, unit)
    assert candidates
    best = candidates[0]
    assert best.verification == "verified"
    # The parameterized rewrite must survive a re-scan.
    rescan = DetectionEngine(detector=NullDetector()).detect_unit(
        unit.model_copy(update={"source": best.source})
    )
    assert not any(f.cwe == "CWE-89" for f in rescan)


def test_deserialization_patch_marked_semantically_risky():
    unit, finding = _finding("def f(d):\n    return pickle.loads(d)")
    candidates = PatchGenerator().generate(finding, unit)
    best = candidates[0]
    assert best.semantic_risk is True
    assert best.verification in {"partially_verified", "verified"}


def test_advisory_patch_when_no_template_applies():
    unit, finding = _finding("def f(p):\n    return hashlib.md5(p)")
    candidates = PatchGenerator().generate(finding, unit)
    assert candidates
    assert "SECURITY" in candidates[0].source


def test_verifier_rejects_unparseable_patch():
    unit, finding = _finding("def f(d):\n    return pickle.loads(d)")
    report = Verifier().verify(unit, "def f(:\n  return", finding)
    assert report.status == "unverified"
    assert report.checks[0]["ok"] is False


def test_diff_is_unified_and_small():
    unit, finding = _finding('def f(q):\n    cur.execute("SELECT * FROM t WHERE id = " + q)')
    diff = PatchGenerator().generate(finding, unit)[0].unified_diff
    assert diff.startswith("--- ")
    assert "+++ " in diff
