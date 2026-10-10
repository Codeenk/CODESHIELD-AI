from codeshield.core.severity import cwe_info, known_cwes, owasp_for, severity_for
from codeshield.models import Severity


def test_known_cwes_present():
    assert "CWE-89" in known_cwes()
    assert "CWE-78" in known_cwes()


def test_severity_for_critical_cwe():
    assert severity_for("CWE-89", 0.9) is Severity.critical


def test_low_confidence_caps_high_severity():
    # A shaky high-severity finding is downgraded rather than shown as high.
    assert severity_for("CWE-78", 0.2) is Severity.medium
    assert severity_for("CWE-78", 0.9) is Severity.critical


def test_unknown_cwe_is_neutral():
    info = cwe_info("CWE-99999")
    assert info.name == "Uncategorized Weakness"
    assert info.cwe == "CWE-99999"


def test_cwe_normalised_without_prefix():
    assert cwe_info("89").cwe == "CWE-89"
    assert owasp_for("CWE-89") == "A03:2021"
