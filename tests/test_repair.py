from codeshield.core import rules
from codeshield.core.parsing import analyze_file
from codeshield.core.repair import generate_candidates
from codeshield.core.verify import verify_and_finalize
from codeshield.models import PatchStatus


def _finding_and_analysis(code: str, path: str = "app.py"):
    analysis = analyze_file(path, code)
    findings = rules.scan_text(path, code)
    assert findings, "expected at least one finding"
    return findings[0], analysis


def test_os_system_patch_is_verified():
    code = "import os\n\ndef ping(h):\n    os.system('ping ' + h)\n"
    finding, analysis = _finding_and_analysis(code)
    candidates = generate_candidates(finding, analysis)
    assert candidates
    patch = verify_and_finalize(candidates[0], finding, analysis)
    assert patch.status is PatchStatus.verified
    assert "shell=False" in patch.patched_code
    assert patch.diff.startswith("---")


def test_weak_hash_patch_verified():
    code = "import hashlib\n\ndef f(x):\n    return hashlib.md5(x).hexdigest()\n"
    finding, analysis = _finding_and_analysis(code)
    candidates = generate_candidates(finding, analysis)
    patch = verify_and_finalize(candidates[0], finding, analysis)
    assert patch.status is PatchStatus.verified
    assert "sha256" in patch.patched_code


def test_unparsable_patch_is_unverified():
    code = "def f(x):\n    return eval(x)\n"
    finding, analysis = _finding_and_analysis(code)
    candidates = generate_candidates(finding, analysis)
    candidate = candidates[0]
    # Corrupt the patch so it can no longer parse.
    candidate.patched_code = "def f(x:\n    return x\n"
    candidate.patched_text = "def f(x:\n    return x\n"
    patch = verify_and_finalize(candidate, finding, analysis)
    assert patch.status is PatchStatus.unverified
    assert any("FAILED" in c for c in patch.verification)


def test_verification_never_claims_safe_without_checks():
    code = "import pickle\n\ndef load(b):\n    return pickle.loads(b)\n"
    finding, analysis = _finding_and_analysis(code)
    candidates = generate_candidates(finding, analysis)
    patch = verify_and_finalize(candidates[0], finding, analysis)
    assert patch.verification
    assert any("re-scan" in c for c in patch.verification)
