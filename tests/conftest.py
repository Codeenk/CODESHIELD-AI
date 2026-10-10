"""Shared test configuration.

Tests run with the neural detector disabled so the suite is deterministic and needs no GPU or
network. The CodeBERT path is exercised separately by the optional `model` marker.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("CODESHIELD_DISABLE_MODEL", "1")

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = REPO_ROOT / "examples" / "vulnerable"


@pytest.fixture()
def examples_dir() -> Path:
    return EXAMPLES


@pytest.fixture()
def vulnerable_snippet() -> str:
    return (
        "import sqlite3\n"
        "\n"
        "def get_user(username):\n"
        "    conn = sqlite3.connect('app.db')\n"
        "    cur = conn.cursor()\n"
        "    cur.execute(f\"SELECT * FROM users WHERE name = '{username}'\")\n"
        "    return cur.fetchall()\n"
    )
