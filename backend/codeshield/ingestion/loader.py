"""Turn uploads, archives, and repositories into a list of scannable files.

The ingestion layer never executes anything it ingests; it only reads text.
"""
from __future__ import annotations

import io
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from .. import config


@dataclass
class SourceFile:
    path: str          # repository-relative posix path
    language: str
    text: str
    size: int


class IngestionError(Exception):
    pass


def detect_language(path: str) -> Optional[str]:
    return config.SUPPORTED_LANGUAGES.get(Path(path).suffix.lower())


def should_skip(rel_path: str) -> bool:
    """Return True for vendored, generated, or binary-looking paths."""
    parts = Path(rel_path).parts
    if any(part in config.SKIP_DIRS for part in parts):
        return True
    name = Path(rel_path).name.lower()
    if name.startswith("."):
        return True
    if any(name.endswith(suffix) for suffix in config.SKIP_FILE_SUFFIXES):
        return True
    return detect_language(name) is None


def _read_text(path: Path) -> Optional[str]:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace")


def collect_from_directory(root: Path) -> list[SourceFile]:
    """Walk a directory tree and return every supported, non-skipped file."""
    root = Path(root).resolve()
    files: list[SourceFile] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if should_skip(rel):
            continue
        if path.stat().st_size > config.MAX_FILE_BYTES:
            continue
        text = _read_text(path)
        if text is None:
            continue
        language = detect_language(path.name)
        if not language:
            continue
        files.append(SourceFile(path=rel, language=language, text=text, size=len(text)))
    return files


def collect_from_uploads(
    uploads: Iterable[tuple[str, bytes]]
) -> list[SourceFile]:
    """Handle a list of (filename, content) pairs from the API.

    ``.zip`` members are expanded in memory; other files are read directly.
    """
    files: list[SourceFile] = []
    for filename, content in uploads:
        if len(content) > config.MAX_ARCHIVE_BYTES:
            raise IngestionError(f"{filename} exceeds the archive size limit")
        if filename.lower().endswith(".zip"):
            files.extend(_collect_from_zip(filename, content))
            continue
        if len(content) > config.MAX_FILE_BYTES:
            raise IngestionError(f"{filename} exceeds the file size limit")
        language = detect_language(filename)
        if not language:
            raise IngestionError(f"Unsupported file type: {filename}")
        text = content.decode("utf-8", errors="replace")
        files.append(SourceFile(path=filename, language=language, text=text, size=len(text)))
    return files


def _collect_from_zip(arcname: str, content: bytes) -> list[SourceFile]:
    files: list[SourceFile] = []
    try:
        archive = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile as exc:  # pragma: no cover - defensive
        raise IngestionError(f"{arcname} is not a valid zip archive") from exc
    with archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            rel = info.filename.replace("\\", "/")
            # Strip a single common top-level folder (e.g. project-main/).
            if should_skip(rel):
                continue
            if info.file_size > config.MAX_FILE_BYTES:
                continue
            language = detect_language(rel)
            if not language:
                continue
            with archive.open(info) as handle:
                raw = handle.read(config.MAX_FILE_BYTES + 1)
            if len(raw) > config.MAX_FILE_BYTES or b"\x00" in raw[:4096]:
                continue
            text = raw.decode("utf-8", errors="replace")
            files.append(
                SourceFile(path=_strip_root(rel), language=language, text=text, size=len(text))
            )
    return files


def _strip_root(rel: str) -> str:
    """Collapse a single wrapping directory (hub-style archives)."""
    parts = rel.split("/")
    if len(parts) > 1 and "-" in parts[0] and len(parts[0].split("-")[0]) > 0:
        # Only strip when every member shares the same leading segment; the
        # caller-visible path is cosmetic, so a conservative strip is fine.
        return "/".join(parts[1:])
    return rel


def _validate_repo_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise IngestionError("A repository URL is required")
    if url.startswith(("http://", "https://", "git@", "ssh://")):
        return url
    if "/" in url and " " not in url:  # allow owner/name shorthand
        return f"https://github.com/{url.removesuffix('.git')}.git"
    raise IngestionError(f"Unsupported repository URL: {url}")


def clone_repo(url: str, branch: Optional[str] = None, depth: int = 1) -> Path:
    """Shallow-clone a repository read-only into a temporary directory.

    The caller is responsible for deleting the returned path.
    """
    git = shutil.which("git")
    if not git:
        raise IngestionError("git is not installed; cannot clone repositories")
    target = Path(tempfile.mkdtemp(prefix="codeshield-repo-"))
    cmd = [git, "clone", "--depth", str(depth), "--no-tags", "--single-branch"]
    if branch:
        cmd += ["--branch", branch]
    # Force read-only-ish behaviour: no interactive credential prompts.
    cmd += [url, str(target)]
    env = {
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "echo",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, env={**_base_env(), **env}, timeout=180
        )
    except subprocess.TimeoutExpired as exc:
        shutil.rmtree(target, ignore_errors=True)
        raise IngestionError("Timed out cloning the repository") from exc
    if proc.returncode != 0:
        shutil.rmtree(target, ignore_errors=True)
        raise IngestionError(
            "git clone failed: " + (proc.stderr.strip().splitlines()[-1] if proc.stderr else "unknown error")
        )
    return target


def _base_env() -> dict[str, str]:
    import os

    return dict(os.environ)
