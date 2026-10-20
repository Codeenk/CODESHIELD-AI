"""Bounded ingestion for snippets, uploads, archives, and validated Git repositories."""
from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Iterable, Optional
from urllib.parse import urlparse

from .. import config

_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")
_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,120}$")


class IngestionError(ValueError):
    pass


@dataclass
class Workspace:
    root: Path
    files: dict[str, str]
    source_type: str
    target: str
    meta: dict = field(default_factory=dict)

    @property
    def repo_path(self) -> Optional[Path]:
        return self.root if self.source_type == "repo" else None

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def __enter__(self) -> "Workspace":
        return self

    def __exit__(self, *exc) -> None:
        self.cleanup()


def language_for(path: str) -> Optional[str]:
    suffix = PurePosixPath(path).suffix.lower()
    return config.SUPPORTED_LANGUAGES.get(suffix)


def _safe_relative(name: str) -> str:
    normalized = name.replace("\\", "/").lstrip("/")
    parts = [p for p in normalized.split("/") if p not in {"", "."}]
    if not parts or any(p == ".." for p in parts):
        raise IngestionError("Archive contains an unsafe path")
    joined = "/".join(parts)
    if len(joined) > 300:
        raise IngestionError("Archive contains an excessively long path")
    return joined


def _decode(data: bytes) -> Optional[str]:
    if b"\x00" in data[:4096]:
        return None
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


def _temp_root(prefix: str = "codeshield-") -> Path:
    base = Path(tempfile.gettempdir())
    return Path(tempfile.mkdtemp(prefix=prefix, dir=base))


def _iter_zip_members(archive: zipfile.ZipFile) -> Iterable[tuple[zipfile.ZipInfo, str]]:
    infos = archive.infolist()
    if len(infos) > config.MAX_ZIP_ENTRIES:
        raise IngestionError(
            f"Archive has too many entries ({len(infos)} > {config.MAX_ZIP_ENTRIES})"
        )
    names = []
    for info in infos:
        if info.is_dir():
            continue
        mode = (info.external_attr >> 16) & 0o170000
        if mode == 0o120000:
            continue
        relative = _safe_relative(info.filename)
        names.append(relative)
        yield info, relative
    if not names:
        raise IngestionError("Archive contains no files")


def _strip_common_prefix(names: list[str]) -> dict[str, str]:
    if not names:
        return {}
    parts = [n.split("/") for n in names]
    if len(parts) > 1 and all(len(p) > 1 for p in parts):
        first = parts[0][0]
        if all(p[0] == first for p in parts):
            return {n: n[len(first) + 1:] for n in names}
    return {n: n for n in names}


def workspace_from_zip(filename: str, data: bytes) -> Workspace:
    if len(data) > config.MAX_ARCHIVE_BYTES:
        raise IngestionError("Archive exceeds the configured size limit")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise IngestionError("File is not a valid ZIP archive") from exc
    root = _temp_root("codeshield-zip-")
    collected: dict[str, bytes] = {}
    total = 0
    try:
        with archive:
            members = list(_iter_zip_members(archive))
            mapping = _strip_common_prefix([rel for _, rel in members])
            for info, relative in members:
                path = mapping[relative]
                if not language_for(path):
                    continue
                if info.file_size > config.MAX_FILE_BYTES:
                    continue
                if info.compress_size and info.file_size > 1024 * 1024:
                    if info.file_size / max(info.compress_size, 1) > 200:
                        raise IngestionError("Archive appears to be a zip bomb")
                total += info.file_size
                if total > config.MAX_ARCHIVE_BYTES:
                    raise IngestionError("Archive expands beyond the configured size limit")
                if len(collected) >= config.MAX_FILES:
                    raise IngestionError("Archive contains too many source files")
                with archive.open(info) as handle:
                    payload = handle.read(config.MAX_FILE_BYTES + 1)
                if len(payload) > config.MAX_FILE_BYTES:
                    continue
                collected[path] = payload
        if not collected:
            raise IngestionError("Archive contains no supported source files")
        files: dict[str, str] = {}
        for path, payload in collected.items():
            text = _decode(payload)
            if text is None:
                continue
            destination = root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text, encoding="utf-8")
            files[path] = text
        return Workspace(
            root=root, files=files, source_type="zip",
            target=f"{filename} ({len(files)} files)",
            meta={"archive": filename},
        )
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise


def workspace_from_uploads(uploads: Iterable[tuple[str, bytes]]) -> Workspace:
    root = _temp_root("codeshield-upload-")
    files: dict[str, str] = {}
    total = 0
    try:
        for index, (name, payload) in enumerate(uploads):
            relative = _safe_relative(name or f"file_{index}.txt")
            if len(payload) > config.MAX_FILE_BYTES:
                raise IngestionError(f"{relative} exceeds the per-file size limit")
            total += len(payload)
            if total > config.MAX_TOTAL_BYTES:
                raise IngestionError("Upload exceeds the configured total size limit")
            if len(files) >= config.MAX_FILES:
                raise IngestionError("Too many files in upload")
            if not language_for(relative):
                continue
            text = _decode(payload)
            if text is None:
                continue
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text, encoding="utf-8")
            files[relative] = text
        if not files:
            raise IngestionError(
                "No supported source files found. Supported: "
                + ", ".join(sorted(set(config.SUPPORTED_LANGUAGES)))
            )
        return Workspace(
            root=root, files=files, source_type="upload",
            target=f"Uploaded files ({len(files)} files)", meta={},
        )
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise


def workspace_from_snippet(filename: str, code: str) -> Workspace:
    relative = _safe_relative(filename or "snippet.py")
    if not language_for(relative):
        raise IngestionError(
            "Unsupported snippet language. Use a .py, .js, .ts, .jsx, .tsx, or .java file."
        )
    if len(code.encode("utf-8")) > config.MAX_FILE_BYTES:
        raise IngestionError("Snippet exceeds the per-file size limit")
    root = _temp_root("codeshield-snippet-")
    try:
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(code, encoding="utf-8")
        return Workspace(
            root=root, files={relative: code}, source_type="snippet",
            target=relative, meta={},
        )
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise


def validate_repo_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise IngestionError("Repository URL is required")
    if any(token in url for token in ("ext::", "::", "\n", "\r", "\x00")):
        raise IngestionError("Repository URL contains an unsupported protocol")
    parsed = urlparse(url)
    if parsed.scheme not in config.ALLOWED_REPO_SCHEMES:
        raise IngestionError(
            f"Repository scheme must be one of: {', '.join(sorted(config.ALLOWED_REPO_SCHEMES))}"
        )
    if parsed.username or parsed.password:
        raise IngestionError("Credentials in repository URLs are not allowed")
    host = (parsed.hostname or "").lower()
    if host not in config.ALLOWED_REPO_HOSTS:
        raise IngestionError(
            f"Repository host must be one of: {', '.join(sorted(config.ALLOWED_REPO_HOSTS))}"
        )
    path = parsed.path.strip("/")
    if not path or " " in path:
        raise IngestionError("Repository URL must include a valid owner/repository path")
    return url


def _repo_env() -> dict[str, str]:
    env = {
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/true",
        "GIT_ALLOW_PROTOCOL": "https",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GCM_INTERACTIVE": "never",
        "LC_ALL": "C",
    }
    return env


def clone_repo(
    url: str, branch: Optional[str] = None, commit: Optional[str] = None
) -> Workspace:
    url = validate_repo_url(url)
    if branch and not _BRANCH_RE.match(branch):
        raise IngestionError("Invalid branch name")
    if branch and ".." in branch:
        raise IngestionError("Invalid branch name")
    if commit and not _COMMIT_RE.match(commit):
        raise IngestionError("Commit must be a 7-40 character hexadecimal SHA")

    root = _temp_root("codeshield-repo-")
    target = root / "repo"
    command = [
        "git", "clone", "--depth", "1", "--single-branch", "--no-tags",
        "--recurse-submodules=no", "--no-local",
    ]
    if branch:
        command += ["--branch", branch]
    command += ["--", url, str(target)]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=config.REPO_TIMEOUT,
            env=_repo_env(),
        )
        if result.returncode != 0:
            raise IngestionError(_clean_git_error(result.stderr or result.stdout))
        if commit:
            fetch = subprocess.run(
                ["git", "-C", str(target), "fetch", "--depth", "1", "origin", commit],
                capture_output=True, text=True, timeout=config.REPO_TIMEOUT, env=_repo_env(),
            )
            if fetch.returncode != 0:
                raise IngestionError("Requested commit is not reachable in this repository")
            checkout = subprocess.run(
                ["git", "-C", str(target), "-c", "advice.detachedHead=false", "checkout", "--detach", "FETCH_HEAD"],
                capture_output=True, text=True, timeout=60, env=_repo_env(),
            )
            if checkout.returncode != 0:
                raise IngestionError("Could not check out the requested commit")
        head = subprocess.run(
            ["git", "-C", str(target), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=20, env=_repo_env(),
        )
        sha = head.stdout.strip() if head.returncode == 0 else ""
        files = _collect_repo(target)
        return Workspace(
            root=target, files=files, source_type="repo", target=url,
            meta={"commit": sha, "branch": branch or "", "requested_url": url},
        )
    except subprocess.TimeoutExpired as exc:
        shutil.rmtree(root, ignore_errors=True)
        raise IngestionError("Repository clone timed out") from exc
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise


def _clean_git_error(message: str) -> str:
    text = (message or "").strip().splitlines()
    last = text[-1] if text else "Repository could not be cloned"
    last = re.sub(r"https://[^@\s]+@", "https://", last)
    return last[:300]


def _collect_repo(root: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    total = 0
    for path in root.rglob("*"):
        relative_path = path.relative_to(root)
        if any(part in config.SKIP_DIRS for part in relative_path.parts):
            continue
        if not path.is_file() or path.is_symlink():
            continue
        relative = relative_path.as_posix()
        if relative.endswith(config.SKIP_FILE_SUFFIXES) or not language_for(relative):
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > config.MAX_FILE_BYTES:
            continue
        total += size
        if total > config.REPO_MAX_BYTES:
            raise IngestionError("Repository exceeds the configured source size limit")
        if len(files) >= config.MAX_FILES:
            raise IngestionError("Repository contains too many supported source files")
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "\x00" in text[:4096]:
            continue
        files[relative] = text
    if not files:
        raise IngestionError("Repository contains no supported Python, JavaScript, TypeScript, or Java files")
    return files
