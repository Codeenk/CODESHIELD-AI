"""Central configuration for CodeShield AI.

Everything is overridable through environment variables so the same code runs
in development, in a test, and inside Docker without edits.
"""
from __future__ import annotations

import os
from pathlib import Path

# --- Paths -----------------------------------------------------------------
PACKAGE_DIR = Path(__file__).resolve().parent          # backend/codeshield
BACKEND_DIR = PACKAGE_DIR.parent                        # backend
REPO_DIR = BACKEND_DIR.parent                           # repository root
KNOWLEDGE_DIR = PACKAGE_DIR / "knowledge"
VULN_KB_DIR = KNOWLEDGE_DIR / "vulnerabilities"
FRONTEND_DIR = REPO_DIR / "frontend"
FRONTEND_DIST = FRONTEND_DIR / "dist"
SAMPLES_DIR = REPO_DIR / "samples"
DATA_DIR = Path(os.environ.get("CODESHIELD_DATA_DIR", BACKEND_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = Path(os.environ.get("CODESHIELD_DB", DATA_DIR / "codeshield.db"))


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


# --- Detection model -------------------------------------------------------
# The public binary insecure-code classifier used as our starting checkpoint.
DETECTION_MODEL_ID = os.environ.get(
    "CODESHIELD_MODEL", "mrm8488/codebert-base-finetuned-detect-insecure-code"
)
# "auto"  -> use the model if transformers + weights are available, else rules
# "on"    -> require the model (fail loudly if unavailable)
# "off"   -> rules only (fast, no downloads)
MODEL_MODE = os.environ.get("CODESHIELD_MODEL_MODE", "auto").strip().lower()
MODEL_MAX_TOKENS = int(os.environ.get("CODESHIELD_MODEL_MAX_TOKENS", "512"))
# The reference checkpoint is a weak binary classifier (65.3% accuracy on Devign,
# C/C++-only) that flags most functions as insecure. It is therefore used to
# *corroborate* rule findings, not to raise findings on its own. Standalone
# "model-only" findings are opt-in and must clear a high threshold.
MODEL_ONLY = _env_bool("CODESHIELD_MODEL_ONLY", False)
MODEL_ONLY_THRESHOLD = float(os.environ.get("CODESHIELD_MODEL_ONLY_THRESHOLD", "0.95"))

# --- Repair ----------------------------------------------------------------
# Optional text-generation model id for LLM repair. Empty => template repair.
REPAIR_MODEL_ID = os.environ.get("CODESHIELD_REPAIR_MODEL", "").strip()
REPAIR_MAX_CANDIDATES = int(os.environ.get("CODESHIELD_REPAIR_MAX_CANDIDATES", "3"))

# --- Sandbox / verification ------------------------------------------------
# Executing a project's own tests is opt-in and never happens by default.
RUN_TESTS = _env_bool("CODESHIELD_RUN_TESTS", False)
TEST_TIMEOUT_SECONDS = int(os.environ.get("CODESHIELD_TEST_TIMEOUT", "60"))

# --- API / security --------------------------------------------------------
API_TOKEN = os.environ.get("CODESHIELD_API_TOKEN", "").strip()
MAX_FILE_BYTES = int(os.environ.get("CODESHIELD_MAX_FILE_BYTES", str(5 * 1024 * 1024)))
MAX_ARCHIVE_BYTES = int(os.environ.get("CODESHIELD_MAX_ARCHIVE_BYTES", str(50 * 1024 * 1024)))

SUPPORTED_LANGUAGES = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
}

# Directories and file patterns skipped during ingestion.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "dist", "build", "out", "target",
    "vendor", "__pycache__", ".venv", "venv", "env", ".tox", ".mypy_cache",
    ".pytest_cache", "coverage", ".next", ".nuxt", "site-packages",
}
SKIP_FILE_SUFFIXES = (
    ".min.js", ".min.css", ".map", ".lock", ".bundle.js", ".chunk.js",
)

CWE_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
