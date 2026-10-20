#!/usr/bin/env python
"""Seed the local database with demo scans so the dashboard is not empty.

Usage:
    python backend/scripts/seed_demo.py
    python backend/scripts/seed_demo.py --reset
"""
from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from codeshield import auth, config, db, store  # noqa: E402
from codeshield.pipeline import run_scan  # noqa: E402
from codeshield.schemas import Scan  # noqa: E402


def _collect(root: Path) -> list[tuple[str, bytes]]:
    files = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in config.SUPPORTED_LANGUAGES:
            continue
        relative = path.relative_to(root).as_posix()
        files.append((relative, path.read_bytes()))
    return files


def seed(reset: bool = False) -> int:
    db.init_db()
    if reset:
        with db.session() as conn:
            conn.execute("DELETE FROM findings")
            conn.execute("DELETE FROM scans")
            conn.execute("DELETE FROM projects")
    user = auth.ensure_demo_user()
    samples = config.REPO_DIR / "samples"
    created = 0
    for directory in ("vulnerable", "clean"):
        root = samples / directory
        if not root.is_dir():
            continue
        uploads = _collect(root)
        if not uploads:
            continue
        project = store.ensure_project(user.id, f"Demo {directory} sample")
        scan = Scan(
            id=uuid.uuid4().hex,
            user_id=user.id,
            project_id=project.id,
            project_name=project.name,
            target=f"{directory} sample",
            source_type="upload",
            config={"generate_patches": True, "model_mode": "off"},
        )
        store.create_scan(scan)
        previous_provider = config.REPAIR_PROVIDER
        previous_base_url = config.LLM_BASE_URL
        config.REPAIR_PROVIDER = "none"
        config.LLM_BASE_URL = ""
        try:
            run_scan(scan, {"type": "upload", "files": uploads})
        finally:
            config.REPAIR_PROVIDER = previous_provider
            config.LLM_BASE_URL = previous_base_url
        store.save_scan_results(scan, scan.findings)
        created += 1
        print(
            f"seeded {directory}: {scan.summary.total_findings} findings "
            f"across {scan.summary.files_scanned} files ({scan.id})"
        )
    print(f"demo user: {user.email} (password demo1234)")
    print(f"database: {config.DB_PATH}")
    return created


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed CodeShield demo data.")
    parser.add_argument("--reset", action="store_true", help="Delete existing scans first")
    args = parser.parse_args()
    if not seed(reset=args.reset):
        print("no sample files found", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
