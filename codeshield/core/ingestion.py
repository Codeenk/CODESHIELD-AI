"""Stage 1 — code ingestion (PRD §7.1 FR-1..FR-4).

Accepts uploaded files/zips and public GitHub repository URLs, then filters vendored,
generated and binary files so only real source reaches the scanner. Cloning is read-only and
shallow.
"""

from __future__ import annotations

import io
import os
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass

from ..config import Settings, get_settings
from .parsing import detect_language, sha256_text

SKIP_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    "out",
    "vendor",
    "third_party",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".next",
    ".nuxt",
    "coverage",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "target",
    ".gradle",
    ".idea",
    ".vscode",
}

SKIP_SUFFIXES = (
    ".min.js",
    ".min.css",
    ".map",
    ".lock",
    ".svg",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".jar",
    ".class",
    ".so",
    ".dll",
    ".exe",
)


@dataclass
class IngestedFile:
    path: str          # display path (repo-relative)
    text: str
    language: str
    size: int
    sha256: str
    skipped: bool = False
    skip_reason: str | None = None


def _decode(data: bytes) -> str | None:
    if b"\x00" in data[:4096]:
        return None  # binary
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


def should_skip_path(path: str) -> str | None:
    parts = path.replace("\\", "/").split("/")
    for part in parts[:-1]:
        if part in SKIP_DIRS:
            return f"vendored/generated directory '{part}'"
    name = parts[-1].lower()
    if any(name.endswith(suffix) for suffix in SKIP_SUFFIXES):
        return "generated/asset file"
    return None


def read_file(path: str, display_path: str | None = None, settings: Settings | None = None) -> IngestedFile:
    settings = settings or get_settings()
    display = display_path or path
    with open(path, "rb") as handle:
        data = handle.read()

    language = detect_language(display)
    if language is None:
        return IngestedFile(display, "", "text", len(data), "", True, "unsupported file type")
    if len(data) > settings.max_file_bytes:
        return IngestedFile(
            display, "", language, len(data), "", True, "file exceeds size limit"
        )
    reason = should_skip_path(display)
    if reason:
        return IngestedFile(display, "", language, len(data), "", True, reason)

    text = _decode(data)
    if text is None:
        return IngestedFile(display, "", language, len(data), "", True, "binary file")
    return IngestedFile(display, text, language, len(text), sha256_text(text))


def ingest_directory(
    root: str, settings: Settings | None = None, prefix: str = ""
) -> list[IngestedFile]:
    """Walk a directory and ingest every supported source file."""
    settings = settings or get_settings()
    files: list[IngestedFile] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".git")]
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            display = f"{prefix}{rel.replace(os.sep, '/')}" if prefix else rel.replace(os.sep, "/")
            try:
                files.append(read_file(full, display, settings))
            except OSError:
                continue
    return files


def ingest_upload(
    filename: str, data: bytes, settings: Settings | None = None
) -> list[IngestedFile]:
    """Ingest an uploaded file, or every supported file inside an uploaded zip."""
    settings = settings or get_settings()
    if filename.lower().endswith(".zip"):
        return _ingest_zip(filename, data, settings)

    language = detect_language(filename)
    if language is None:
        return [IngestedFile(filename, "", "text", len(data), "", True, "unsupported file type")]
    if len(data) > settings.max_file_bytes:
        return [IngestedFile(filename, "", language, len(data), "", True, "file exceeds size limit")]

    text = _decode(data)
    if text is None:
        return [IngestedFile(filename, "", language, len(data), "", True, "binary file")]
    return [IngestedFile(filename, text, language, len(text), sha256_text(text))]


def _ingest_zip(filename: str, data: bytes, settings: Settings) -> list[IngestedFile]:
    if len(data) > settings.max_archive_bytes:
        return [IngestedFile(filename, "", "zip", len(data), "", True, "archive exceeds size limit")]

    out: list[IngestedFile] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                name = info.filename
                if name.startswith("__MACOSX") or name.startswith("."):
                    continue
                language = detect_language(name)
                if language is None:
                    continue
                reason = should_skip_path(name)
                if reason:
                    out.append(IngestedFile(name, "", language, info.file_size, "", True, reason))
                    continue
                if info.file_size > settings.max_file_bytes:
                    out.append(
                        IngestedFile(name, "", language, info.file_size, "", True, "file exceeds size limit")
                    )
                    continue
                payload = archive.read(info)
                text = _decode(payload)
                if text is None:
                    out.append(IngestedFile(name, "", language, len(payload), "", True, "binary file"))
                    continue
                out.append(IngestedFile(name, text, language, len(text), sha256_text(text)))
    except zipfile.BadZipFile:
        return [IngestedFile(filename, "", "zip", len(data), "", True, "invalid zip archive")]
    return out


# --------------------------------------------------------------------------- #
# GitHub
# --------------------------------------------------------------------------- #

GITHUB_HOSTS = ("https://github.com/", "http://github.com/", "git@github.com:")


def _valid_repo_url(url: str) -> bool:
    return url.startswith(GITHUB_HOSTS) and not url.startswith("-")


def ingest_github(
    repo_url: str,
    ref: str | None = None,
    settings: Settings | None = None,
    workdir: str | None = None,
) -> tuple[list[IngestedFile], str]:
    """Clone a public GitHub repo read-only (shallow) and ingest its source files.

    Returns ``(files, local_path)``. Raises ``ValueError`` for a rejected URL.
    """
    if not _valid_repo_url(repo_url):
        raise ValueError("Only https://github.com/<owner>/<repo> URLs are accepted")

    settings = settings or get_settings()
    target = workdir or tempfile.mkdtemp(prefix="codeshield-repo-")
    cmd = ["git", "clone", "--depth", "1", "--single-branch"]
    if ref:
        cmd += ["--branch", ref]
    cmd += ["--", repo_url, target]

    completed = subprocess.run(
        cmd, capture_output=True, text=True, timeout=300, check=False
    )
    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout or "git clone failed").strip().splitlines()
        raise RuntimeError(message[-1] if message else "git clone failed")

    repo_name = repo_url.rstrip("/").split("/")[-1].removesuffix(".git")
    return ingest_directory(target, settings, prefix=f"{repo_name}/"), target
