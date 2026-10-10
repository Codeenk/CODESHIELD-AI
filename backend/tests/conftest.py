"""Pytest fixtures and environment isolation.

Force rules-only detection (fast, no model download) and an isolated database
*before* importing any CodeShield module, since config reads env at import time.
"""
import os
import pathlib
import sys
import tempfile

BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

os.environ["CODESHIELD_MODEL_MODE"] = "off"
_TMP = tempfile.mkdtemp(prefix="codeshield-test-")
os.environ["CODESHIELD_DATA_DIR"] = _TMP
os.environ["CODESHIELD_DB"] = os.path.join(_TMP, "test.db")
os.environ.pop("CODESHIELD_API_TOKEN", None)

import pytest  # noqa: E402

from codeshield.schemas import CodeUnit, Finding  # noqa: E402

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
