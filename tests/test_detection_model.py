"""Tests for the real CodeBERT detector path.

These require `torch`/`transformers` and the downloaded checkpoint (``requirements-ml.txt``).
When the neural stack is not installed they SKIP rather than silently pass — the rules-only
suite in the other test modules always runs. In the verification environment that produced
docs/TRACEABILITY.md the model was installed, so these tests executed.
"""

from __future__ import annotations

import pytest

from codeshield.config import Settings
from codeshield.core.detection import CodeBERTDetector, model_only_severity
from codeshield.core.ingestion import IngestedFile
from codeshield.core.parsing import sha256_text
from codeshield.core.scan import Scanner, ScanOptions
from codeshield.models import Engine, Severity

VULN = "import os\n\ndef ping(host):\n    return os.system('ping -c 1 ' + host)\n"


def _enabled_settings() -> Settings:
    # conftest disables the model globally; the model tests opt back in explicitly.
    return Settings(disable_model=False)


@pytest.fixture(scope="module")
def detector() -> CodeBERTDetector:
    instance = CodeBERTDetector(_enabled_settings())
    if not instance.available():
        pytest.skip(f"neural detector unavailable: {instance.load_error}")
    return instance


# --------------------------------------------------------------------------- #
# Pure logic — always runs, no model needed
# --------------------------------------------------------------------------- #


def test_model_only_severity_is_capped_at_medium():
    # A model-only hit must never outrank medium, even for a critical CWE.
    assert model_only_severity("CWE-78", 0.99) is Severity.medium
    assert model_only_severity("CWE-89", 1.0) is Severity.medium
    # Low-severity classes are not raised.
    assert model_only_severity("CWE-328", 0.9) is Severity.medium
    assert model_only_severity("CWE-000", 0.9) is Severity.medium
    assert model_only_severity("CWE-79", 0.9) is Severity.medium


# --------------------------------------------------------------------------- #
# Model path — requires the downloaded checkpoint
# --------------------------------------------------------------------------- #


def test_detector_loads_and_predicts(detector):
    prediction = detector.predict(VULN)
    assert prediction is not None
    assert 0.0 <= prediction.probability <= 1.0
    assert prediction.cwe.startswith("CWE-")
    assert detector.version == _enabled_settings().model_id


def test_attention_is_available_for_the_heatmap(detector):
    """Regression: transformers>=5 defaults to sdpa attention, which silently returns no
    attentions and left the line-level heat-map empty (FR-15). We force eager attention."""
    prediction = detector.predict(VULN)
    assert prediction is not None
    assert prediction.attention, "expected non-empty attention after forcing eager attention"
    lines = {row.line for row in prediction.attention}
    assert lines <= {1, 2, 3, 4}
    assert all(0.0 <= row.score <= 1.0 for row in prediction.attention)


def test_clean_and_vulnerable_are_both_scored_provably(detector):
    """The checkpoint is weakly discriminative on clean code (see scripts/eval_model.py);
    we assert the mechanics, not an accuracy claim we cannot support."""
    prediction = detector.predict("def add(a, b):\n    return a + b\n")
    assert prediction is not None
    assert 0.0 <= prediction.probability <= 1.0


def test_scan_with_model_upgrades_agreement_to_both():
    ingested = IngestedFile("cmd.py", VULN, "python", len(VULN), sha256_text(VULN))
    scan = Scanner(ScanOptions(settings=_enabled_settings())).scan([ingested], source="model-test")

    assert scan.model_version
    assert any("Neural detector active" in note for note in scan.engine_notes)
    # The vulnerable function is caught by both engines when they agree.
    assert any(f.engine is Engine.both for f in scan.findings)


def test_model_only_findings_never_exceed_medium():
    # A benign function the checkpoint is known to over-flag should be model-only and capped.
    code = "def add(a, b):\n    return a + b\n"
    ingested = IngestedFile("clean.py", code, "python", len(code), sha256_text(code))
    scan = Scanner(ScanOptions(settings=_enabled_settings())).scan([ingested], source="model-test")

    for finding in scan.findings:
        if finding.engine is Engine.model:
            assert finding.severity.rank <= Severity.medium.rank
            assert "unconfirmed" in finding.title
