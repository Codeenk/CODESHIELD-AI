"""SQLite persistence for scans and findings.

A connection is opened per operation so the store is safe to use from FastAPI's
thread pool without sharing a sqlite handle across threads.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Optional

from .. import config
from ..schemas import Finding, Scan

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    created_at TEXT,
    target TEXT,
    source_type TEXT,
    status TEXT,
    error TEXT,
    summary TEXT,
    config TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT,
    status TEXT,
    cwe TEXT,
    severity TEXT,
    engine TEXT,
    path TEXT,
    function TEXT,
    fingerprint TEXT,
    data TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint, status);
"""


class Store:
    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = Path(db_path or config.DB_PATH)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    # -- scans -------------------------------------------------------------
    def save_scan(self, scan: Scan, status: Optional[str] = None) -> None:
        scan.status = status or scan.status  # type: ignore[assignment]
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?,?,?)",
                (
                    scan.id,
                    scan.created_at.isoformat(),
                    scan.target,
                    scan.source_type,
                    scan.status,
                    scan.error,
                    scan.summary.model_dump_json(),
                    json.dumps(scan.config),
                ),
            )
            # Re-save findings so lifecycle statuses track the latest scan run.
            for finding in scan.findings:
                self._save_finding(conn, scan.id, finding)

    def _save_finding(self, conn: sqlite3.Connection, scan_id: str, finding: Finding) -> None:
        conn.execute(
            "INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                finding.id,
                scan_id,
                finding.status,
                finding.cwe,
                finding.severity,
                finding.engine,
                finding.path,
                finding.function,
                finding.fingerprint,
                finding.model_dump_json(),
            ),
        )

    def get_scan(self, scan_id: str) -> Optional[Scan]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if row is None:
                return None
            findings = []
            for frow in conn.execute(
                "SELECT data FROM findings WHERE scan_id = ? ORDER BY severity, path", (scan_id,)
            ):
                findings.append(Finding.model_validate_json(frow["data"]))
            scan = Scan(
                id=row["id"],
                target=row["target"],
                source_type=row["source_type"],
                status=row["status"],
                error=row["error"],
                config=json.loads(row["config"] or "{}"),
            )
            scan.created_at = scan.created_at.fromisoformat(row["created_at"])
            scan.summary = scan.summary.model_validate_json(row["summary"])
            scan.findings = findings
            return scan

    def list_scans(self, limit: int = 50, offset: int = 0) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, created_at, target, source_type, status, summary "
                "FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        out = []
        for row in rows:
            summary = json.loads(row["summary"] or "{}")
            out.append(
                {
                    "id": row["id"],
                    "created_at": row["created_at"],
                    "target": row["target"],
                    "source_type": row["source_type"],
                    "status": row["status"],
                    "total_findings": summary.get("total_findings", 0),
                    "by_severity": summary.get("by_severity", {}),
                }
            )
        return out

    def get_scan_files(self, scan_id: str) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT DISTINCT path, function, start_line, end_line FROM findings WHERE scan_id = ?",
                (scan_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    # -- findings ----------------------------------------------------------
    def get_finding(self, finding_id: str) -> Optional[tuple[str, Finding]]:
        with self._conn() as conn:
            row = conn.execute("SELECT scan_id, data FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if row is None:
            return None
        return row["scan_id"], Finding.model_validate_json(row["data"])

    def update_finding_status(self, finding_id: str, status: str) -> bool:
        with self._conn() as conn:
            row = conn.execute("SELECT data FROM findings WHERE id = ?", (finding_id,)).fetchone()
            if row is None:
                return False
            finding = Finding.model_validate_json(row["data"])
            finding.status = status  # type: ignore[assignment]
            conn.execute(
                "UPDATE findings SET status = ?, data = ? WHERE id = ?",
                (status, finding.model_dump_json(), finding_id),
            )
        return True

    def suppressed_fingerprints(self) -> set[str]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT DISTINCT fingerprint FROM findings WHERE status = 'false_positive'"
            ).fetchall()
        return {r["fingerprint"] for r in rows if r["fingerprint"]}

    def delete_scan(self, scan_id: str) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
