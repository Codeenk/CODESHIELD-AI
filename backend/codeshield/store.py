"""Persistence operations for projects, scans, findings, suppressions, and analytics."""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timedelta
from typing import Any, Iterable, Optional

from . import config, db
from .schemas import (
    CompareFinding, Finding, Project, Scan, ScanComparison, ScanSummary,
    StatusUpdate, utcnow,
)


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:60] or "project"


def _json(model) -> str:
    return json.dumps(model.model_dump(mode="json"), default=str)


def _scan_from_row(row, findings: Optional[list[Finding]] = None) -> Scan:
    summary = ScanSummary.model_validate_json(row["summary_json"] or "{}")
    config_data = json.loads(row["config_json"] or "{}")
    return Scan(
        id=row["id"],
        user_id=row["user_id"],
        project_id=row["project_id"],
        project_name=row["project_name"] if "project_name" in row.keys() else "",
        created_at=datetime.fromisoformat(row["created_at"]),
        started_at=datetime.fromisoformat(row["started_at"]) if row["started_at"] else None,
        finished_at=datetime.fromisoformat(row["finished_at"]) if row["finished_at"] else None,
        target=row["target"],
        source_type=row["source_type"],
        status=row["status"],
        stage=row["stage"],
        progress=row["progress"],
        error=row["error"],
        summary=summary,
        config=config_data,
        findings=findings or [],
    )


def ensure_project(user_id: str, name: str, conn=None) -> Project:
    name = " ".join(name.split())[:80] or "Untitled project"
    slug = slugify(name)
    owns = conn is None
    conn = conn or db.connect()
    try:
        row = conn.execute(
            "SELECT * FROM projects WHERE user_id = ? AND slug = ?", (user_id, slug)
        ).fetchone()
        if not row:
            project_id = uuid.uuid4().hex
            conn.execute(
                "INSERT INTO projects (id, user_id, name, slug, created_at) VALUES (?,?,?,?,?)",
                (project_id, user_id, name, slug, utcnow().isoformat()),
            )
            row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        if owns:
            conn.commit()
        return Project(
            id=row["id"], user_id=row["user_id"], name=row["name"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )
    finally:
        if owns:
            conn.close()


def get_project(project_id: str, user_id: str) -> Optional[Project]:
    with db.session() as conn:
        row = conn.execute(
            "SELECT * FROM projects WHERE id = ? AND user_id = ?", (project_id, user_id)
        ).fetchone()
    return Project(
        id=row["id"], user_id=row["user_id"], name=row["name"],
        created_at=datetime.fromisoformat(row["created_at"]),
    ) if row else None


def list_projects(user_id: str) -> list[Project]:
    with db.session() as conn:
        rows = conn.execute(
            "SELECT p.*, COUNT(s.id) AS scan_count, MAX(s.created_at) AS last_scan_at"
            " FROM projects p LEFT JOIN scans s ON s.project_id = p.id"
            " WHERE p.user_id = ? GROUP BY p.id ORDER BY COALESCE(MAX(s.created_at), p.created_at) DESC",
            (user_id,),
        ).fetchall()
        open_rows = conn.execute(
            "SELECT f.project_id AS project_id, COUNT(*) AS n FROM findings f JOIN scans s ON s.id = f.scan_id"
            " WHERE s.user_id = ? AND f.status = 'open' AND f.suppressed = 0 GROUP BY f.project_id",
            (user_id,),
        ).fetchall()
    open_map = {r["project_id"]: r["n"] for r in open_rows}
    return [
        Project(
            id=r["id"], user_id=r["user_id"], name=r["name"],
            created_at=datetime.fromisoformat(r["created_at"]),
            scan_count=r["scan_count"] or 0,
            last_scan_at=datetime.fromisoformat(r["last_scan_at"]) if r["last_scan_at"] else None,
            open_findings=open_map.get(r["id"], 0),
        )
        for r in rows
    ]


def create_scan(scan: Scan) -> Scan:
    with db.session() as conn:
        conn.execute(
            "INSERT INTO scans (id, user_id, project_id, target, source_type, status, stage,"
            " progress, error, summary_json, config_json, created_at, started_at, finished_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                scan.id, scan.user_id, scan.project_id, scan.target, scan.source_type,
                scan.status, scan.stage, scan.progress, scan.error,
                _json(scan.summary), json.dumps(scan.config, default=str),
                scan.created_at.isoformat(),
                scan.started_at.isoformat() if scan.started_at else None,
                scan.finished_at.isoformat() if scan.finished_at else None,
            ),
        )
    return scan


def update_scan_progress(
    scan_id: str, stage: str, progress: int, status: str = "running"
) -> None:
    with db.session() as conn:
        conn.execute(
            "UPDATE scans SET stage = ?, progress = ?, status = ?,"
            " started_at = COALESCE(started_at, ?) WHERE id = ?",
            (stage, max(0, min(100, progress)), status, utcnow().isoformat(), scan_id),
        )


def fail_scan(scan_id: str, error: str) -> None:
    with db.session() as conn:
        conn.execute(
            "UPDATE scans SET status = 'failed', stage = 'failed', error = ?,"
            " finished_at = ?, progress = 100 WHERE id = ?",
            (error[:2000], utcnow().isoformat(), scan_id),
        )


def cancel_scan(scan_id: str) -> None:
    with db.session() as conn:
        conn.execute(
            "UPDATE scans SET status = 'cancelled', stage = 'cancelled', progress = 100,"
            " finished_at = ? WHERE id = ? AND status IN ('queued','running')",
            (utcnow().isoformat(), scan_id),
        )


def active_scan_count(user_id: str) -> int:
    with db.session() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM scans WHERE user_id = ? AND status IN ('queued','running')",
            (user_id,),
        ).fetchone()
    return int(row["n"]) if row else 0


def is_cancelled(scan_id: str) -> bool:
    with db.session() as conn:
        row = conn.execute("SELECT status FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return bool(row and row["status"] == "cancelled")


def save_scan_results(scan: Scan, findings: list[Finding]) -> None:
    with db.session() as conn:
        conn.execute(
            "UPDATE scans SET status = ?, stage = ?, progress = 100, error = NULL,"
            " summary_json = ?, finished_at = ? WHERE id = ?",
            (
                scan.status, scan.stage, _json(scan.summary),
                (scan.finished_at or utcnow()).isoformat(), scan.id,
            ),
        )
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan.id,))
        for finding in findings:
            conn.execute(
                "INSERT INTO findings (id, scan_id, project_id, fingerprint, status,"
                " suppressed, data_json, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (
                    finding.id, scan.id, finding.project_id, finding.fingerprint,
                    finding.status, int(finding.suppressed), _json(finding),
                    finding.created_at.isoformat(),
                ),
            )


def _findings_for(conn, scan_id: str) -> list[Finding]:
    rows = conn.execute(
        "SELECT data_json FROM findings WHERE scan_id = ?", (scan_id,)
    ).fetchall()
    findings = [Finding.model_validate_json(r["data_json"]) for r in rows]
    findings.sort(
        key=lambda f: (-config.SEVERITY_ORDER.get(f.severity, 0), -f.confidence, f.path, f.start_line)
    )
    return findings


def get_scan(scan_id: str, user_id: Optional[str] = None, with_findings: bool = True) -> Optional[Scan]:
    with db.session() as conn:
        sql = (
            "SELECT s.*, p.name AS project_name FROM scans s"
            " LEFT JOIN projects p ON p.id = s.project_id WHERE s.id = ?"
        )
        params: tuple[Any, ...] = (scan_id,)
        if user_id:
            sql += " AND s.user_id = ?"
            params += (user_id,)
        row = conn.execute(sql, params).fetchone()
        if not row:
            return None
        findings = _findings_for(conn, scan_id) if with_findings else []
    return _scan_from_row(row, findings)


def list_scans(
    user_id: str, project_id: Optional[str] = None, status: Optional[str] = None,
    limit: int = 50, offset: int = 0,
) -> tuple[list[Scan], int]:
    where = ["s.user_id = ?"]
    params: list[Any] = [user_id]
    if project_id:
        where.append("s.project_id = ?")
        params.append(project_id)
    if status:
        where.append("s.status = ?")
        params.append(status)
    clause = " AND ".join(where)
    with db.session() as conn:
        total = conn.execute(f"SELECT COUNT(*) AS n FROM scans s WHERE {clause}", params).fetchone()["n"]
        rows = conn.execute(
            f"SELECT s.*, p.name AS project_name FROM scans s"
            f" LEFT JOIN projects p ON p.id = s.project_id WHERE {clause}"
            f" ORDER BY s.created_at DESC LIMIT ? OFFSET ?",
            (*params, max(1, min(limit, 200)), max(0, offset)),
        ).fetchall()
    return [_scan_from_row(r) for r in rows], total


def delete_scan(scan_id: str, user_id: str) -> bool:
    with db.session() as conn:
        cur = conn.execute("DELETE FROM scans WHERE id = ? AND user_id = ?", (scan_id, user_id))
        return cur.rowcount > 0


def get_finding(finding_id: str, user_id: Optional[str] = None) -> Optional[Finding]:
    with db.session() as conn:
        sql = (
            "SELECT f.data_json FROM findings f JOIN scans s ON s.id = f.scan_id WHERE f.id = ?"
        )
        params: tuple[Any, ...] = (finding_id,)
        if user_id:
            sql += " AND s.user_id = ?"
            params += (user_id,)
        row = conn.execute(sql, params).fetchone()
    return Finding.model_validate_json(row["data_json"]) if row else None


def update_finding_status(
    finding_id: str, update: StatusUpdate, user_id: str, scan_id: Optional[str] = None,
) -> Optional[Finding]:
    with db.session() as conn:
        row = conn.execute(
            "SELECT f.*, s.user_id FROM findings f JOIN scans s ON s.id = f.scan_id"
            " WHERE f.id = ? AND s.user_id = ?",
            (finding_id, user_id),
        ).fetchone()
        if not row:
            return None
        finding = Finding.model_validate_json(row["data_json"])
        finding.status = update.status
        suppressed = update.status in {"false_positive", "accepted_risk"}
        finding.suppressed = suppressed
        conn.execute(
            "UPDATE findings SET status = ?, suppressed = ?, data_json = ? WHERE id = ?",
            (finding.status, int(suppressed), _json(finding), finding_id),
        )
        if finding.project_id:
            if suppressed:
                conn.execute(
                    "INSERT INTO suppressions (id, project_id, fingerprint, reason, status,"
                    " user_id, created_at) VALUES (?,?,?,?,?,?,?)"
                    " ON CONFLICT(project_id, fingerprint) DO UPDATE SET"
                    " reason = excluded.reason, status = excluded.status,"
                    " user_id = excluded.user_id, created_at = excluded.created_at",
                    (
                        uuid.uuid4().hex, finding.project_id, finding.fingerprint,
                        update.note, update.status, user_id, utcnow().isoformat(),
                    ),
                )
            else:
                conn.execute(
                    "DELETE FROM suppressions WHERE project_id = ? AND fingerprint = ?",
                    (finding.project_id, finding.fingerprint),
                )
        conn.execute(
            "INSERT INTO finding_events (id, finding_id, scan_id, status, note, user_id, created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (
                uuid.uuid4().hex, finding_id, row["scan_id"], update.status,
                update.note, user_id, utcnow().isoformat(),
            ),
        )
    return finding


def suppression_map(project_id: str) -> dict[str, str]:
    if not project_id:
        return {}
    with db.session() as conn:
        rows = conn.execute(
            "SELECT fingerprint, status FROM suppressions WHERE project_id = ?", (project_id,)
        ).fetchall()
    return {r["fingerprint"]: r["status"] for r in rows}


def finding_events(finding_id: str) -> list[dict[str, Any]]:
    with db.session() as conn:
        rows = conn.execute(
            "SELECT status, note, user_id, created_at FROM finding_events"
            " WHERE finding_id = ? ORDER BY created_at DESC",
            (finding_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def compare_scans(base: Scan, head: Scan) -> ScanComparison:
    base_fps = {f.fingerprint: f for f in base.findings}
    head_fps = {f.fingerprint: f for f in head.findings}

    def item(f: Finding, status: str) -> CompareFinding:
        return CompareFinding(
            fingerprint=f.fingerprint, cwe=f.cwe, cwe_title=f.cwe_title,
            severity=f.severity, path=f.path, function=f.function,
            line=f.start_line, status=status,
        )

    new = [item(f, "new") for fp, f in head_fps.items() if fp not in base_fps]
    fixed = [item(f, "fixed") for fp, f in base_fps.items() if fp not in head_fps]
    recurring = [item(f, "recurring") for fp, f in head_fps.items() if fp in base_fps]
    return ScanComparison(
        base_scan=base.id, head_scan=head.id, new=new, fixed=fixed, recurring=recurring,
        resolved=len(fixed), introduced=len(new), unchanged=len(recurring),
    )


def stats(user_id: str, days: int = 14) -> dict[str, Any]:
    since = (utcnow() - timedelta(days=days - 1)).date().isoformat()
    with db.session() as conn:
        scan_count = conn.execute(
            "SELECT COUNT(*) AS n FROM scans WHERE user_id = ?", (user_id,)
        ).fetchone()["n"]
        running = conn.execute(
            "SELECT COUNT(*) AS n FROM scans WHERE user_id = ? AND status IN ('queued','running')",
            (user_id,),
        ).fetchone()["n"]
        counts = conn.execute(
            "SELECT f.status, f.suppressed,"
            " json_extract(f.data_json,'$.severity') AS severity,"
            " json_extract(f.data_json,'$.cwe') AS cwe,"
            " json_extract(f.data_json,'$.engine') AS engine"
            " FROM findings f JOIN scans s ON s.id = f.scan_id WHERE s.user_id = ?",
            (user_id,),
        ).fetchall()
        trend_rows = conn.execute(
            "SELECT substr(s.created_at,1,10) AS day, COUNT(*) AS scans"
            " FROM scans s WHERE s.user_id = ? AND substr(s.created_at,1,10) >= ?"
            " GROUP BY day ORDER BY day",
            (user_id, since),
        ).fetchall()
        recent = conn.execute(
            "SELECT s.*, p.name AS project_name FROM scans s"
            " LEFT JOIN projects p ON p.id = s.project_id"
            " WHERE s.user_id = ? ORDER BY s.created_at DESC LIMIT 6",
            (user_id,),
        ).fetchall()
        projects = conn.execute(
            "SELECT COUNT(*) AS n FROM projects WHERE user_id = ?", (user_id,)
        ).fetchone()["n"]
        fix_times = conn.execute(
            "SELECT e.created_at AS fixed_at, f.data_json AS data"
            " FROM finding_events e JOIN findings f ON f.id = e.finding_id"
            " JOIN scans s ON s.id = f.scan_id WHERE s.user_id = ? AND e.status = 'fixed'",
            (user_id,),
        ).fetchall()

    severity: dict[str, int] = {}
    cwe: dict[str, int] = {}
    engine: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    open_total = 0
    suppressed = 0
    for row in counts:
        if row["suppressed"]:
            suppressed += 1
            continue
        status_counts[row["status"]] = status_counts.get(row["status"], 0) + 1
        if row["status"] == "open":
            open_total += 1
        severity[row["severity"] or "unknown"] = severity.get(row["severity"] or "unknown", 0) + 1
        cwe[row["cwe"] or "unknown"] = cwe.get(row["cwe"] or "unknown", 0) + 1
        engine[row["engine"] or "rules"] = engine.get(row["engine"] or "rules", 0) + 1

    mttr_hours = None
    if fix_times:
        deltas = []
        for row in fix_times:
            try:
                finding = json.loads(row["data"])
                created = datetime.fromisoformat(finding["created_at"])
                fixed = datetime.fromisoformat(row["fixed_at"])
                deltas.append((fixed - created).total_seconds() / 3600)
            except (ValueError, KeyError, TypeError):
                continue
        if deltas:
            mttr_hours = round(sum(deltas) / len(deltas), 1)

    trend = []
    by_day = {r["day"]: r["scans"] for r in trend_rows}
    with db.session() as conn:
        daily_findings = conn.execute(
            "SELECT substr(s.created_at,1,10) AS day, COUNT(f.id) AS n"
            " FROM scans s LEFT JOIN findings f ON f.scan_id = s.id AND f.suppressed = 0"
            " WHERE s.user_id = ? AND substr(s.created_at,1,10) >= ? GROUP BY day",
            (user_id, since),
        ).fetchall()
    finding_days = {r["day"]: r["n"] for r in daily_findings}
    today = utcnow().date()
    for offset in range(days - 1, -1, -1):
        day = (today - timedelta(days=offset)).isoformat()
        trend.append({"day": day, "scans": by_day.get(day, 0), "findings": finding_days.get(day, 0)})

    return {
        "scans": scan_count,
        "active_scans": running,
        "projects": projects,
        "findings": open_total,
        "suppressed": suppressed,
        "by_severity": severity,
        "by_cwe": dict(sorted(cwe.items(), key=lambda kv: -kv[1])[:8]),
        "by_engine": engine,
        "by_status": status_counts,
        "trend": trend,
        "mttr_hours": mttr_hours,
        "recent_scans": [_scan_from_row(r) for r in recent],
    }


def recent_fingerprints(user_id: str, limit: int = 200) -> list[str]:
    with db.session() as conn:
        rows = conn.execute(
            "SELECT DISTINCT f.fingerprint FROM findings f JOIN scans s ON s.id = f.scan_id"
            " WHERE s.user_id = ? ORDER BY f.created_at DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
    return [r["fingerprint"] for r in rows]


def mark_stale_scans() -> int:
    with db.session() as conn:
        rows = conn.execute(
            "SELECT id FROM scans WHERE status IN ('queued','running')"
        ).fetchall()
        for row in rows:
            conn.execute(
                "UPDATE scans SET status = 'failed', stage = 'interrupted', error = ?,"
                " finished_at = ?, progress = 100 WHERE id = ?",
                ("Scan interrupted by a server restart", utcnow().isoformat(), row["id"]),
            )
        return len(rows)
