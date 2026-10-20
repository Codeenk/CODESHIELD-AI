"""Configuration for CodeShield AI, fully overridable through environment variables."""
from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "CodeShield AI"
VERSION = "3.0.0"
PACKAGE_DIR = Path(__file__).resolve().parent
BACKEND_DIR = PACKAGE_DIR.parent
REPO_DIR = BACKEND_DIR.parent
KNOWLEDGE_DIR = PACKAGE_DIR / "knowledge"
VULN_KB_DIR = KNOWLEDGE_DIR / "vulnerabilities"
FRONTEND_DIR = REPO_DIR / "frontend"
FRONTEND_DIST = FRONTEND_DIR / "dist"
SAMPLES_DIR = REPO_DIR / "samples"
MODELS_DIR = Path(os.environ.get("CODESHIELD_MODELS_DIR", REPO_DIR / "models"))
DATA_DIR = Path(os.environ.get("CODESHIELD_DATA_DIR", BACKEND_DIR / "data"))
DB_PATH = Path(os.environ.get("CODESHIELD_DB", DATA_DIR / "codeshield.db"))


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)))
    except ValueError:
        return default


def _env_list(name: str, default: str) -> list[str]:
    raw = os.environ.get(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


DATA_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)

# --- Runtime ---------------------------------------------------------------
HOST = os.environ.get("CODESHIELD_HOST", "127.0.0.1")
PORT = _env_int("CODESHIELD_PORT", 8000)
LOG_LEVEL = os.environ.get("CODESHIELD_LOG_LEVEL", "INFO").upper()
JOB_WORKERS = max(1, _env_int("CODESHIELD_JOB_WORKERS", 3))

# --- Authentication --------------------------------------------------------
# on = email/password (local) + optional GitHub OAuth. off = single local user.
AUTH_MODE = os.environ.get("CODESHIELD_AUTH", "on").strip().lower()
SESSION_TTL_DAYS = _env_int("CODESHIELD_SESSION_TTL_DAYS", 30)
COOKIE_NAME = os.environ.get("CODESHIELD_COOKIE_NAME", "cs_session")
COOKIE_SECURE = _env_bool("CODESHIELD_COOKIE_SECURE", False)
FRONTEND_URL = os.environ.get("CODESHIELD_FRONTEND_URL", "http://127.0.0.1:8000").rstrip("/")
GITHUB_CLIENT_ID = os.environ.get("CODESHIELD_GITHUB_CLIENT_ID", "").strip()
GITHUB_CLIENT_SECRET = os.environ.get("CODESHIELD_GITHUB_CLIENT_SECRET", "").strip()
GITHUB_REDIRECT_URI = os.environ.get(
    "CODESHIELD_GITHUB_REDIRECT_URI", f"{FRONTEND_URL}/api/v1/auth/github/callback"
)
API_TOKEN = os.environ.get("CODESHIELD_API_TOKEN", "").strip()
OAUTH_STATE_SECRET = os.environ.get("CODESHIELD_SECRET_KEY", "dev-only-change-me").strip()
MAX_ACTIVE_SCANS = max(1, _env_int("CODESHIELD_MAX_ACTIVE_SCANS", 3))
CORS_ORIGINS = _env_list("CODESHIELD_CORS_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173")

# --- Detection model -------------------------------------------------------
DETECTION_MODEL_ID = os.environ.get(
    "CODESHIELD_MODEL", "mrm8488/codebert-base-finetuned-detect-insecure-code"
)
DETECTION_MODEL_DIR = Path(
    os.environ.get("CODESHIELD_MODEL_DIR", MODELS_DIR / "detector")
)
MODEL_MODE = os.environ.get("CODESHIELD_MODEL_MODE", "auto").strip().lower()
ALLOW_MODEL_DOWNLOAD = _env_bool("CODESHIELD_ALLOW_MODEL_DOWNLOAD", False)
MODEL_MAX_TOKENS = _env_int("CODESHIELD_MODEL_MAX_TOKENS", 512)
MODEL_ONLY = _env_bool("CODESHIELD_MODEL_ONLY", False)
MODEL_ONLY_THRESHOLD = _env_float("CODESHIELD_MODEL_ONLY_THRESHOLD", 0.92)
MODEL_AGREE_THRESHOLD = _env_float("CODESHIELD_MODEL_AGREE_THRESHOLD", 0.75)
MODEL_DISAGREE_THRESHOLD = _env_float("CODESHIELD_MODEL_DISAGREE_THRESHOLD", 0.35)
CALIBRATION_A = _env_float("CODESHIELD_CALIBRATION_A", 1.0)
CALIBRATION_B = _env_float("CODESHIELD_CALIBRATION_B", 0.0)
ATTENTION_MAX_TOKENS = _env_int("CODESHIELD_ATTENTION_MAX_TOKENS", 256)
OCCLUSION_BUDGET = _env_int("CODESHIELD_OCCLUSION_BUDGET", 48)
ATTENTION_FINDING_LIMIT = _env_int("CODESHIELD_ATTENTION_FINDING_LIMIT", 40)

# --- Repair ----------------------------------------------------------------
REPAIR_MODEL_ID = os.environ.get("CODESHIELD_REPAIR_MODEL", "").strip()
REPAIR_PROVIDER = os.environ.get("CODESHIELD_REPAIR_PROVIDER", "auto").strip().lower()
REPAIR_MAX_CANDIDATES = _env_int("CODESHIELD_REPAIR_MAX_CANDIDATES", 3)
LLM_BASE_URL = os.environ.get("CODESHIELD_LLM_BASE_URL", "").strip()
LLM_API_KEY = os.environ.get("CODESHIELD_LLM_API_KEY", "").strip()
LLM_MODEL = os.environ.get("CODESHIELD_LLM_MODEL", "qwen2.5-coder-7b-instruct").strip()
LLM_TIMEOUT = _env_int("CODESHIELD_LLM_TIMEOUT", 90)
LLM_MAX_TOKENS = _env_int("CODESHIELD_LLM_MAX_TOKENS", 1600)
LLM_TEMPERATURE = _env_float("CODESHIELD_LLM_TEMPERATURE", 0.15)
if REPAIR_PROVIDER == "auto":
    REPAIR_PROVIDER = "llm" if (LLM_BASE_URL or REPAIR_MODEL_ID) else "none"
MAX_PATCH_FINDINGS = _env_int("CODESHIELD_MAX_PATCH_FINDINGS", 100)

# --- Verification sandbox --------------------------------------------------
SANDBOX_MODE = os.environ.get("CODESHIELD_SANDBOX", "auto").strip().lower()
SANDBOX_IMAGE = os.environ.get("CODESHIELD_SANDBOX_IMAGE", "codeshield-sandbox:latest")
RUN_TESTS = _env_bool("CODESHIELD_RUN_TESTS", False)
TEST_TIMEOUT = _env_int("CODESHIELD_TEST_TIMEOUT", 120)
TEST_COMMAND = os.environ.get("CODESHIELD_TEST_COMMAND", "python -m pytest -q").split()
SANDBOX_MEMORY = os.environ.get("CODESHIELD_SANDBOX_MEMORY", "1g")
SANDBOX_CPUS = os.environ.get("CODESHIELD_SANDBOX_CPUS", "1")

# --- Privacy / retention ---------------------------------------------------
RETAIN_CODE = _env_bool("CODESHIELD_RETAIN_CODE", False)
MASK_SECRETS = _env_bool("CODESHIELD_MASK_SECRETS", True)

# --- Ingestion -------------------------------------------------------------
MAX_FILE_BYTES = _env_int("CODESHIELD_MAX_FILE_BYTES", 5 * 1024 * 1024)
MAX_ARCHIVE_BYTES = _env_int("CODESHIELD_MAX_ARCHIVE_BYTES", 50 * 1024 * 1024)
MAX_TOTAL_BYTES = _env_int("CODESHIELD_MAX_TOTAL_BYTES", 80 * 1024 * 1024)
MAX_FILES = _env_int("CODESHIELD_MAX_FILES", 4000)
MAX_ZIP_ENTRIES = _env_int("CODESHIELD_MAX_ZIP_ENTRIES", 4000)
REPO_TIMEOUT = _env_int("CODESHIELD_REPO_TIMEOUT", 180)
REPO_MAX_BYTES = _env_int("CODESHIELD_REPO_MAX_BYTES", 120 * 1024 * 1024)
ALLOWED_REPO_SCHEMES = set(_env_list("CODESHIELD_REPO_SCHEMES", "https"))
ALLOWED_REPO_HOSTS = set(
    _env_list("CODESHIELD_REPO_HOSTS", "github.com,gitlab.com,bitbucket.org")
)

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

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "dist", "build", "out", "target",
    "vendor", "__pycache__", ".venv", "venv", "env", ".tox", ".mypy_cache",
    ".pytest_cache", "coverage", ".next", ".nuxt", "site-packages", "bower_components",
}
SKIP_FILE_SUFFIXES = (
    ".min.js", ".min.css", ".map", ".lock", ".bundle.js", ".chunk.js",
)

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
