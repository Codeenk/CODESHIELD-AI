from codeshield import config
from codeshield.sandbox.runner import TestRunner as Runner


def make_workspace(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_ok.py").write_text("def test_ok():\n    assert True\n")
    files = {"tests/test_ok.py": "def test_ok():\n    assert True\n"}
    return Runner(tmp_path, files)


def test_sandbox_off_disables_dynamic_tests(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "RUN_TESTS", True)
    monkeypatch.setattr(config, "SANDBOX_MODE", "off")
    runner = make_workspace(tmp_path)
    assert runner.has_tests
    assert not runner.enabled
    outcome = runner.run("app.py", "print('x')\n")
    assert outcome.status == "skipped"
    assert "disabled" in outcome.detail.lower()


def test_subprocess_mode_enables_tests(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "RUN_TESTS", True)
    monkeypatch.setattr(config, "SANDBOX_MODE", "subprocess")
    runner = make_workspace(tmp_path)
    assert runner.enabled
