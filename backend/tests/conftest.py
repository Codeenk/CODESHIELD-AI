"""Pytest fixtures and environment isolation.

Force rules-only detection (fast, no model download), an isolated database, and
a disabled test sandbox *before* importing any CodeShield module, since config
reads the environment at import time.
"""
import os
import pathlib
import sys
import tempfile
import uuid

BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

os.environ["CODESHIELD_MODEL_MODE"] = "off"
os.environ["CODESHIELD_AUTH"] = "off"
os.environ["CODESHIELD_REPAIR_PROVIDER"] = "none"
os.environ["CODESHIELD_RUN_TESTS"] = "false"
os.environ["CODESHIELD_SANDBOX"] = "disabled"
_TMP = tempfile.mkdtemp(prefix="codeshield-test-")
os.environ["CODESHIELD_DATA_DIR"] = _TMP
os.environ["CODESHIELD_DB"] = os.path.join(_TMP, "test.db")
os.environ.pop("CODESHIELD_API_TOKEN", None)

import pytest  # noqa: E402

from codeshield.detection.engine import build_findings  # noqa: E402
from codeshield.parsing.parser import parse_file  # noqa: E402
from codeshield.pipeline import run_scan  # noqa: E402
from codeshield.schemas import CodeUnit, Scan  # noqa: E402

PY_VULN = '''\
import os, pickle, hashlib

def get_user(q):
    cur.execute("SELECT * FROM users WHERE id = " + q)
    return cur.fetchone()

def run(cmd):
    os.system("ls " + cmd)

def load(data):
    return pickle.loads(data)

def safe(q):
    cur.execute("SELECT * FROM users WHERE id = ?", (q,))
    return cur.fetchone()
'''

JS_VULN = '''\
function login(user) {
  db.query("SELECT * FROM users WHERE name = '" + user + "'");
}
const render = (name) => { el.innerHTML = name; };
'''


def make_unit(source: str, path: str = "a.py", name: str = "") -> CodeUnit:
    parsed = parse_file(path, source)
    assert parsed.units, parsed.error
    unit = parsed.units[0]
    return unit.model_copy(update={"name": name}) if name else unit


def detect(source: str, path: str = "a.py"):
    return build_findings([make_unit(source, path)], enable_model=False).findings


@pytest.fixture()
def py_unit():
    return CodeUnit(path="a.py", language="python", name="get_user",
                    start_line=1, end_line=2,
                    source='def get_user(q):\n    cur.execute("SELECT * FROM users WHERE id = " + q)')


@pytest.fixture()
def py_vuln_unit():
    return CodeUnit(path="a.py", language="python", name="get_user",
                    start_line=1, end_line=3,
                    source='def get_user(q):\n    cur.execute("SELECT * FROM users WHERE id = " + q)\n    return cur.fetchone()')


def scan_source(source: dict, *, patches: bool = True, project_id=None) -> Scan:
    scan = Scan(
        id=uuid.uuid4().hex, project_id=project_id, target="sample",
        source_type=source.get("type", "snippet"),
        config={"generate_patches": patches, "model_mode": "off"},
    )
    return run_scan(scan, source)


@pytest.fixture()
def scan_snippet():
    def _run(code: str, filename: str = "app.py") -> Scan:
        return scan_source({"type": "snippet", "filename": filename, "code": code})
    return _run
