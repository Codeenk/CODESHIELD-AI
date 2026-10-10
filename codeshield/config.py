"""Runtime configuration for CodeShield AI.

All settings come from environment variables (see ``.env.example``) with conservative,
privacy-first defaults. Nothing here performs I/O beyond reading ``os.environ``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


@dataclass
class Settings:
    """Resolved configuration for one process."""

    model_id: str = "mrm8488/codebert-base-finetuned-detect-insecure-code"
    disable_model: bool = False
    model_threshold: float = 0.55

    max_file_bytes: int = 5 * 1024 * 1024
    max_archive_bytes: int = 50 * 1024 * 1024

    retain_code: bool = False

    api_token: str = ""
    host: str = "127.0.0.1"
    port: int = 8000

    repair_endpoint: str = ""
    repair_model: str = "Qwen/Qwen2.5-Coder-7B-Instruct"
    repair_api_key: str = ""

    supported_languages: tuple[str, ...] = field(
        default_factory=lambda: ("python", "javascript", "typescript", "java")
    )

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            model_id=os.environ.get(
                "CODESHIELD_MODEL_ID",
                "mrm8488/codebert-base-finetuned-detect-insecure-code",
            ),
            disable_model=_flag("CODESHIELD_DISABLE_MODEL", False),
            model_threshold=_float("CODESHIELD_MODEL_THRESHOLD", 0.55),
            max_file_bytes=_int("CODESHIELD_MAX_FILE_MB", 5) * 1024 * 1024,
            max_archive_bytes=_int("CODESHIELD_MAX_ARCHIVE_MB", 50) * 1024 * 1024,
            retain_code=_flag("CODESHIELD_RETAIN_CODE", False),
            api_token=os.environ.get("CODESHIELD_API_TOKEN", ""),
            host=os.environ.get("CODESHIELD_HOST", "127.0.0.1"),
            port=_int("CODESHIELD_PORT", 8000),
            repair_endpoint=os.environ.get("CODESHIELD_REPAIR_ENDPOINT", ""),
            repair_model=os.environ.get(
                "CODESHIELD_REPAIR_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct"
            ),
            repair_api_key=os.environ.get("CODESHIELD_REPAIR_API_KEY", ""),
        )


def get_settings() -> Settings:
    """Return settings for the current process (re-read each call)."""
    return Settings.from_env()
