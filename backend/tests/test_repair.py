from conftest import make_unit

from codeshield.detection.rules import detect_unit
from codeshield.repair.patcher import build_patches


def _finding(src: str):
    unit = make_unit(src)
    hits = detect_unit(unit)
    assert hits
    from codeshield.detection.engine import build_findings

    finding = build_findings([unit], enable_model=False).findings[0]
    return unit, finding, hits


def test_sql_patch_is_verified_and_removes_finding():
    unit, finding, hits = _finding('def f(q):\n    cur.execute("SELECT * FROM t WHERE id = " + q)')
    candidates = build_patches(finding, unit, hits, allow_llm=False)
    assert candidates
    best = candidates[0]
    assert best.verification in {"verified", "partially_verified"}
    patched = unit.model_copy(update={"source": best.source})
    assert not any(hit.meta["cwe"] == "CWE-89" for hit in detect_unit(patched))


def test_deserialization_patch_marked_semantically_risky():
    unit, finding, hits = _finding("def f(d):\n    return pickle.loads(d)")
    best = build_patches(finding, unit, hits, allow_llm=False)[0]
    assert best.semantic_risk is True
    assert best.verification in {"partially_verified", "verified"}


def test_weak_hash_patch_upgrades_algorithm():
    unit, finding, hits = _finding("def f(p):\n    return hashlib.md5(p)")
    candidates = build_patches(finding, unit, hits, allow_llm=False)
    assert candidates
    assert "sha256" in candidates[0].source


def test_unparseable_source_is_rejected():
    unit, finding, hits = _finding("def f(d):\n    return pickle.loads(d)")
    bad = unit.model_copy(update={"source": "def f(:\n  return"})
    assert build_patches(finding, bad, hits, allow_llm=False) == []


def test_diff_is_unified_and_small():
    unit, finding, hits = _finding('def f(q):\n    cur.execute("SELECT * FROM t WHERE id = " + q)')
    diff = build_patches(finding, unit, hits, allow_llm=False)[0].unified_diff
    assert diff.startswith("--- ")
    assert "+++ " in diff


def test_command_diff_keeps_separate_lines_and_check_fields():
    unit, finding, hits = _finding('def ping(host):\n    os.system("ping -c 1 " + host)')
    best = build_patches(finding, unit, hits, allow_llm=False)[0]
    lines = best.unified_diff.splitlines(keepends=True)
    assert all(line.endswith("\n") for line in lines)
    assert any(line.startswith("-") and "os.system" in line for line in lines)
    assert any(line.startswith("+") and "subprocess" in line for line in lines)
    assert all(isinstance(check.get("passed"), bool) or check.get("passed") is None for check in best.checks)


def test_missing_unit_yields_no_candidates():
    _, finding, hits = _finding("def f(d):\n    return pickle.loads(d)")
    assert build_patches(finding, None, hits, allow_llm=False) == []
