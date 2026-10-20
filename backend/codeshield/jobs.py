"""In-process background scan jobs backed by the scans table."""
from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from . import config, store
from .pipeline import ScanCancelled, run_scan

log = logging.getLogger("codeshield.jobs")
_executor = ThreadPoolExecutor(max_workers=max(1, config.JOB_WORKERS), thread_name_prefix="scan")
_cancelled: set[str] = set()
_active: set[str] = set()
_lock = threading.Lock()


def submit(scan_id: str, source: dict) -> None:
    with _lock:
        _active.add(scan_id)
    _executor.submit(_run, scan_id, source)


def cancel(scan_id: str) -> None:
    with _lock:
        _cancelled.add(scan_id)
        active = scan_id in _active
    if not active:
        store.cancel_scan(scan_id)


def _is_cancelled(scan_id: str) -> bool:
    with _lock:
        flagged = scan_id in _cancelled
    return flagged or store.is_cancelled(scan_id)


def _run(scan_id: str, source: dict) -> None:
    scan = store.get_scan(scan_id, with_findings=False)
    if scan is None:
        _finish(scan_id)
        return
    if scan.status not in {"queued", "running"}:
        _finish(scan_id)
        return

    def progress(stage: str, value: int) -> None:
        if _is_cancelled(scan_id):
            raise ScanCancelled("Scan cancelled")
        store.update_scan_progress(scan_id, stage, value)

    try:
        completed = run_scan(scan, source, progress, lambda: _is_cancelled(scan_id))
        if _is_cancelled(scan_id):
            raise ScanCancelled("Scan cancelled")
        store.save_scan_results(completed, completed.findings)
    except ScanCancelled:
        store.cancel_scan(scan_id)
        log.info("scan %s cancelled", scan_id)
    except Exception as exc:
        log.exception("scan %s failed", scan_id)
        store.fail_scan(scan_id, f"{type(exc).__name__}: {exc}")
    finally:
        _finish(scan_id)


def _finish(scan_id: str) -> None:
    with _lock:
        _active.discard(scan_id)
        _cancelled.discard(scan_id)


def shutdown() -> None:
    _executor.shutdown(wait=False, cancel_futures=True)
