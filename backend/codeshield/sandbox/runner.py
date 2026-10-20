"""Best-effort, opt-in test execution with Docker or a constrained subprocess."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .. import config

_IGNORE = shutil.ignore_patterns(
    ".git", ".hg", ".svn", "node_modules", "dist", "build", "target", "vendor",
    "__pycache__", ".venv", "venv", "env", ".tox", ".pytest_cache", "coverage",
    ".next", ".nuxt", "site-packages",
)
_docker_checked: Optional[bool] = None


def _docker_ready() -> bool:
    global _docker_checked
    if _docker_checked is not None:
        return _docker_checked
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", config.SANDBOX_IMAGE],
            capture_output=True, timeout=5,
        )
        _docker_checked = result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        _docker_checked = False
    return _docker_checked


def _memory_bytes(value: str) -> int:
    match = re.match(r"^\s*(\d+(?:\.\d+)?)\s*([kmg]?)", value.lower())
    if not match:
        return 1024 * 1024 * 1024
    number = float(match.group(1))
    unit = match.group(2)
    factor = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}[unit]
    return int(number * factor)


def _limits() -> None:
    try:
        import resource

        memory = _memory_bytes(config.SANDBOX_MEMORY)
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        resource.setrlimit(resource.RLIMIT_CPU, (config.TEST_TIMEOUT, config.TEST_TIMEOUT))
        resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
        resource.setrlimit(resource.RLIMIT_FSIZE, (20 * 1024 * 1024, 20 * 1024 * 1024))
    except Exception:
        pass


@dataclass
class TestOutcome:
    status: str
    detail: str = ""
    duration_ms: int = 0
    isolation: str = "none"


class TestRunner:
    def __init__(self, workspace_root: Optional[Path], files: dict[str, str]) -> None:
        self.workspace_root = workspace_root
        self.has_tests = bool(workspace_root and _has_tests(workspace_root))
        self.enabled = bool(
            config.RUN_TESTS
            and self.has_tests
            and workspace_root is not None
            and config.SANDBOX_MODE not in {"off", "disabled", "none", "false"}
        )
        self._baseline: Optional[TestOutcome] = None
        self._files = files

    def baseline(self) -> TestOutcome:
        if not self.enabled or self.workspace_root is None:
            return TestOutcome("skipped", "Tests are not enabled")
        if self._baseline is None:
            self._baseline = self._run_tree(self.workspace_root, None, None)
        return self._baseline

    def run(self, relative_path: str, source: str) -> TestOutcome:
        if not self.enabled or self.workspace_root is None:
            if self.has_tests:
                return TestOutcome("skipped", "Test execution is disabled by configuration")
            return TestOutcome("skipped", "No tests found in the project")
        baseline = self.baseline()
        if baseline.status != "passed":
            return TestOutcome("skipped", f"Baseline tests are {baseline.status}; patch test is inconclusive")
        temp = Path(tempfile.mkdtemp(prefix="codeshield-test-"))
        try:
            target = temp / "project"
            shutil.copytree(self.workspace_root, target, ignore=_IGNORE, symlinks=False)
            destination = (target / relative_path).resolve()
            if target.resolve() not in destination.parents:
                return TestOutcome("error", "Refusing to write a patch outside the test workspace")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(source, encoding="utf-8")
            return self._run_tree(target, relative_path, source)
        except (OSError, shutil.Error) as exc:
            return TestOutcome("error", f"Could not prepare the test workspace: {exc}")
        finally:
            shutil.rmtree(temp, ignore_errors=True)

    def _run_tree(self, root: Path, relative_path: Optional[str], source: Optional[str]) -> TestOutcome:
        started = time.monotonic()
        if config.SANDBOX_MODE != "subprocess" and _docker_ready():
            outcome = _run_docker(root)
            if outcome.status != "error":
                outcome.duration_ms = int((time.monotonic() - started) * 1000)
                return outcome
        outcome = _run_subprocess(root)
        outcome.duration_ms = int((time.monotonic() - started) * 1000)
        return outcome


def _has_tests(root: Path) -> bool:
    if (root / "tests").is_dir() or (root / "test").is_dir():
        return True
    for path in root.rglob("test_*.py"):
        if ".git" not in path.parts:
            return True
    for path in root.rglob("*_test.py"):
        if ".git" not in path.parts:
            return True
    return False


def _clean_output(output: str) -> str:
    text = re.sub(r"\x1b\[[0-9;]*m", "", output or "")
    lines = [line for line in text.splitlines() if line.strip()]
    return "\n".join(lines[-12:])[:2000]


def _run_docker(root: Path) -> TestOutcome:
    command = [
        "docker", "run", "--rm", "--network", "none",
        "--memory", config.SANDBOX_MEMORY, "--cpus", config.SANDBOX_CPUS,
        "--pids-limit", "256", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "-v", f"{root}:/src:rw", "-w", "/src",
        config.SANDBOX_IMAGE, *config.TEST_COMMAND,
    ]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=config.TEST_TIMEOUT + 20,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/tmp"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return TestOutcome("error", f"Docker sandbox failed: {exc}", isolation="docker")
    output = _clean_output((result.stdout or "") + "\n" + (result.stderr or ""))
    if result.returncode == 0:
        return TestOutcome("passed", output or "Tests passed", isolation="docker")
    return TestOutcome("failed", output or f"Tests exited with {result.returncode}", isolation="docker")


def _run_subprocess(root: Path) -> TestOutcome:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(root),
        "TMPDIR": str(root / ".tmp"),
        "PYTHONPATH": str(root),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PIP_NO_INDEX": "1",
        "NO_PROXY": "*",
    }
    (root / ".tmp").mkdir(exist_ok=True)
    command = list(config.TEST_COMMAND)
    if command and command[0] in {"python", "python3"}:
        command[0] = sys.executable
    try:
        result = subprocess.run(
            command, cwd=root, capture_output=True, text=True,
            timeout=config.TEST_TIMEOUT, env=env,
            preexec_fn=_limits if os.name == "posix" else None,
            start_new_session=True,
        )
    except subprocess.TimeoutExpired:
        return TestOutcome("failed", f"Tests exceeded {config.TEST_TIMEOUT}s", isolation="subprocess")
    except (OSError, subprocess.SubprocessError) as exc:
        return TestOutcome("error", f"Test runner failed: {exc}", isolation="subprocess")
    output = _clean_output((result.stdout or "") + "\n" + (result.stderr or ""))
    if result.returncode == 0:
        return TestOutcome("passed", output or "Tests passed", isolation="subprocess")
    return TestOutcome("failed", output or f"Tests exited with {result.returncode}", isolation="subprocess")
