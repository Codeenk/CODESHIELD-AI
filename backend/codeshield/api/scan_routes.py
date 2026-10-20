"""Project, scan, finding, comparison, and report endpoints."""
from __future__ import annotations

import re
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, Response

from .. import config, jobs, store
from ..auth import require_user
from ..ingestion.loader import IngestionError, validate_repo_url
from ..reporting.reporter import build_html, build_json, build_pdf, build_sarif
from ..schemas import Project, Scan, StatusUpdate, User

router = APIRouter(prefix="/api/v1", tags=["scans"])
_CHUNK = 1024 * 1024


async def _read_upload(upload: UploadFile, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await upload.read(_CHUNK)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise HTTPException(status_code=413, detail=f"{upload.filename or 'File'} exceeds the size limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _project_name(source_type: str, repo_url: str, filename: str, explicit: str, files: list[UploadFile]) -> str:
    if explicit.strip():
        return explicit.strip()[:80]
    if source_type == "repo" and repo_url:
        name = repo_url.rstrip("/").rsplit("/", 1)[-1]
        return re.sub(r"\.git$", "", name)[:80] or "Repository"
    if source_type == "zip" and filename:
        return re.sub(r"\.zip$", "", filename, flags=re.I)[:80] or "Archive"
    if source_type == "snippet" and filename:
        return f"{filename} snippet"[:80]
    if files:
        return f"Upload · {files[0].filename or 'files'}"[:80]
    return "Ad-hoc scans"


def _resolve_project(user: User, project_id: Optional[str], name: str) -> Project:
    if project_id:
        project = store.get_project(project_id, user.id)
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        return project
    return store.ensure_project(user.id, name)


@router.post("/scans", status_code=202)
async def create_scan(
    request: Request,
    source_type: str = Form(...),
    files: list[UploadFile] = File(default=[]),
    repo_url: str = Form(""),
    branch: str = Form(""),
    commit: str = Form(""),
    filename: str = Form(""),
    code: str = Form(""),
    project_id: str = Form(""),
    project_name: str = Form(""),
    generate_patches: str = Form("true"),
    model_mode: str = Form(""),
    user: User = Depends(require_user),
) -> Scan:
    source_type = (source_type or "").strip().lower()
    generate_patches = generate_patches.strip().lower() not in {"0", "false", "no", "off"}
    if source_type not in {"repo", "snippet", "zip", "upload"}:
        raise HTTPException(status_code=400, detail="source_type must be repo, snippet, zip, or upload")
    if store.active_scan_count(user.id) >= config.MAX_ACTIVE_SCANS:
        raise HTTPException(status_code=429, detail="Too many active scans. Wait for one to finish.")
    if model_mode and model_mode not in {"off", "auto", "on"}:
        raise HTTPException(status_code=400, detail="model_mode must be off, auto, or on")

    source: dict
    target: str
    if source_type == "repo":
        if not repo_url.strip():
            raise HTTPException(status_code=400, detail="Repository URL is required")
        try:
            repo_url = validate_repo_url(repo_url)
        except IngestionError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        target = repo_url
        source = {"type": "repo", "url": repo_url, "branch": branch or None, "commit": commit or None}
    elif source_type == "snippet":
        if not code.strip():
            raise HTTPException(status_code=400, detail="Code is required")
        if len(code.encode("utf-8")) > config.MAX_FILE_BYTES:
            raise HTTPException(status_code=413, detail="Snippet exceeds the size limit")
        filename = filename or "snippet.py"
        target = filename
        source = {"type": "snippet", "filename": filename, "code": code}
    elif source_type == "zip":
        if not files:
            raise HTTPException(status_code=400, detail="A .zip upload is required")
        if len(files) > 1:
            raise HTTPException(status_code=400, detail="Upload a single .zip archive")
        upload = files[0]
        if not (upload.filename or "").lower().endswith(".zip"):
            raise HTTPException(status_code=400, detail="Archive must be a .zip file")
        data = await _read_upload(upload, config.MAX_ARCHIVE_BYTES)
        target = upload.filename or "archive.zip"
        source = {"type": "zip", "filename": target, "data": data}
    else:
        if not files:
            raise HTTPException(status_code=400, detail="At least one source file is required")
        if len(files) > config.MAX_FILES:
            raise HTTPException(status_code=400, detail="Too many files")
        payloads: list[tuple[str, bytes]] = []
        total = 0
        for upload in files:
            data = await _read_upload(upload, config.MAX_FILE_BYTES)
            total += len(data)
            if total > config.MAX_TOTAL_BYTES:
                raise HTTPException(status_code=413, detail="Upload exceeds the total size limit")
            payloads.append((upload.filename or "file.txt", data))
        target = f"{len(payloads)} files"
        source = {"type": "upload", "files": payloads}

    project = _resolve_project(
        user, project_id or None,
        _project_name(source_type, repo_url, filename, project_name, files),
    )
    scan = Scan(
        id=uuid.uuid4().hex, user_id=user.id, project_id=project.id,
        project_name=project.name, target=target, source_type=source_type,
        status="queued", stage="queued",
        config={
            "generate_patches": bool(generate_patches),
            "model_mode": model_mode or config.MODEL_MODE,
            "kind": source_type,
        },
    )
    store.create_scan(scan)
    try:
        jobs.submit(scan.id, source)
    except Exception as exc:
        store.fail_scan(scan.id, f"Could not queue scan: {exc}")
        raise HTTPException(status_code=503, detail="Scan queue is unavailable") from exc
    return scan


@router.get("/scans")
def list_scans(
    project_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user: User = Depends(require_user),
) -> dict:
    items, total = store.list_scans(user.id, project_id, status, limit, offset)
    return {
        "items": [item.model_dump(mode="json", exclude={"findings"}) for item in items],
        "total": total, "limit": limit, "offset": offset,
    }


@router.get("/scans/compare")
def compare(
    base: str = Query(...), head: str = Query(...),
    user: User = Depends(require_user),
):
    if base == head:
        raise HTTPException(status_code=400, detail="Choose two different scans")
    base_scan = store.get_scan(base, user.id)
    head_scan = store.get_scan(head, user.id)
    if not base_scan or not head_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return store.compare_scans(base_scan, head_scan)


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, user: User = Depends(require_user)) -> Scan:
    scan = store.get_scan(scan_id, user.id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/scans/{scan_id}/cancel")
def cancel_scan(scan_id: str, user: User = Depends(require_user)) -> dict:
    scan = store.get_scan(scan_id, user.id, with_findings=False)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in {"queued", "running"}:
        raise HTTPException(status_code=409, detail="Scan is not running")
    jobs.cancel(scan_id)
    return {"ok": True, "status": "cancelling"}


@router.delete("/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: str, user: User = Depends(require_user)) -> Response:
    scan = store.get_scan(scan_id, user.id, with_findings=False)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status in {"queued", "running"}:
        raise HTTPException(status_code=409, detail="Cancel the scan before deleting it")
    store.delete_scan(scan_id, user.id)
    return Response(status_code=204)


@router.get("/scans/{scan_id}/report")
def scan_report(
    scan_id: str,
    fmt: str = Query("json", alias="format", pattern="^(json|sarif|html|pdf)$"),
    download: bool = False,
    user: User = Depends(require_user),
) -> Response:
    scan = store.get_scan(scan_id, user.id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "completed":
        raise HTTPException(status_code=409, detail="Report is available after the scan completes")
    base = re.sub(r"[^A-Za-z0-9_.-]+", "-", scan.project_name or "scan")[:60] or "scan"
    filename = f"{base}-{scan.id[:8]}.{fmt}"
    disposition = "attachment" if download or fmt in {"json", "sarif", "pdf"} else "inline"
    headers = {"Content-Disposition": f'{disposition}; filename="{filename}"'}
    if fmt == "json":
        return Response(build_json(scan), media_type="application/json", headers=headers)
    if fmt == "sarif":
        import json as _json

        return Response(
            _json.dumps(build_sarif(scan), indent=2), media_type="application/sarif+json",
            headers=headers,
        )
    if fmt == "html":
        return HTMLResponse(build_html(scan), headers=headers)
    return Response(build_pdf(scan), media_type="application/pdf", headers=headers)


@router.get("/findings/{finding_id}")
def get_finding(finding_id: str, user: User = Depends(require_user)):
    finding = store.get_finding(finding_id, user.id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/findings/{finding_id}")
def update_finding(
    finding_id: str, payload: StatusUpdate, user: User = Depends(require_user)
):
    finding = store.update_finding_status(finding_id, payload, user.id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.get("/findings/{finding_id}/events")
def finding_events(finding_id: str, user: User = Depends(require_user)) -> list[dict]:
    if not store.get_finding(finding_id, user.id):
        raise HTTPException(status_code=404, detail="Finding not found")
    return store.finding_events(finding_id)


@router.get("/projects")
def list_projects(user: User = Depends(require_user)) -> list[Project]:
    return store.list_projects(user.id)


@router.get("/stats")
def get_stats(days: int = Query(14, ge=7, le=90), user: User = Depends(require_user)) -> dict:
    return store.stats(user.id, days)
