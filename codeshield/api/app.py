"""FastAPI application (PRD §7.7 FR-31, §12).

Endpoints
---------
GET  /health
POST /api/scans                    multipart upload (file or .zip)
POST /api/scans/github             {"url": ..., "ref": ...}
GET  /api/scans                    list scans
GET  /api/scans/{id}               poll status / results
GET  /api/scans/{id}/report        ?format=json|sarif|pdf
GET  /api/scans/{id}/patches/{fid} best patch for a finding
POST /api/scans/{id}/findings/{fid}/status   lifecycle update (FR-28)
GET  /                             dashboard (static)

Auth: when ``CODESHIELD_API_TOKEN`` is set every ``/api`` route requires a matching
``Authorization: Bearer <token>`` header.
"""

from __future__ import annotations

import threading

from fastapi import BackgroundTasks, Depends, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .. import __version__
from ..config import Settings, get_settings
from ..core.detection import CodeBERTDetector
from ..core.ingestion import IngestedFile, ingest_github, ingest_upload
from ..core.scan import Scanner, ScanOptions
from ..models import FindingStatus, ScanResult, ScanStatus, utc_now
from ..report import to_pdf, to_sarif_str


class GithubScanRequest(BaseModel):
    url: str
    ref: str | None = None


class StatusUpdate(BaseModel):
    status: FindingStatus


class ScanStore:
    """A tiny in-memory store. Swap for PostgreSQL/Redis in production (PRD §9 scalability)."""

    def __init__(self) -> None:
        self._scans: dict[str, ScanResult] = {}
        self._lock = threading.Lock()

    def put(self, scan: ScanResult) -> None:
        with self._lock:
            self._scans[scan.id] = scan

    def get(self, scan_id: str) -> ScanResult | None:
        with self._lock:
            return self._scans.get(scan_id)

    def all(self) -> list[ScanResult]:
        with self._lock:
            return list(self._scans.values())


def _run_scan(store: ScanStore, scan_id: str, files: list[IngestedFile], source: str, settings: Settings) -> None:
    scan = store.get(scan_id)
    if scan is None:
        return
    try:
        result = Scanner(ScanOptions(settings=settings)).scan(files, source)
        result.id = scan_id
    except Exception as exc:  # pragma: no cover - defensive
        with store._lock:
            scan.status = ScanStatus.error
            scan.error = f"{exc.__class__.__name__}: {exc}"
            scan.finished_at = utc_now()
        return
    store.put(result)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(
        title="CodeShield AI",
        version=__version__,
        description="AI-powered source code vulnerability scanner & explainable auto-repair engine",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    store = ScanStore()
    app.state.store = store

    def require_token(authorization: str | None = Header(default=None)) -> None:
        if not settings.api_token:
            return
        expected = f"Bearer {settings.api_token}"
        if authorization != expected:
            raise HTTPException(status_code=401, detail="Invalid or missing API token")

    @app.get("/health")
    def health() -> dict:
        detector = CodeBERTDetector(settings)
        model_ready = detector.available()
        return {
            "status": "ok",
            "version": __version__,
            "model_id": settings.model_id,
            "model_available": model_ready,
            "model_note": detector.load_error,
            "auth_required": bool(settings.api_token),
        }

    @app.post("/api/scans", dependencies=[Depends(require_token)])
    async def create_scan(
        background: BackgroundTasks,
        file: UploadFile = File(...),
    ) -> dict:
        raw = await file.read()
        files = ingest_upload(file.filename or "upload", raw, settings)
        scan = ScanResult(source=f"upload:{file.filename}", status=ScanStatus.queued)
        store.put(scan)
        background.add_task(_run_scan, store, scan.id, files, scan.source, settings)
        return {"id": scan.id, "status": scan.status.value, "files": len(files)}

    @app.post("/api/scans/github", dependencies=[Depends(require_token)])
    def create_github_scan(
        request: GithubScanRequest, background: BackgroundTasks
    ) -> dict:
        scan = ScanResult(source=request.url, status=ScanStatus.queued)
        store.put(scan)

        def job() -> None:
            try:
                files, _path = ingest_github(request.url, request.ref, settings)
            except Exception as exc:
                with store._lock:
                    scan.status = ScanStatus.error
                    scan.error = str(exc)
                    scan.finished_at = utc_now()
                return
            _run_scan(store, scan.id, files, scan.source, settings)

        background.add_task(job)
        return {"id": scan.id, "status": scan.status.value}

    @app.get("/api/scans", dependencies=[Depends(require_token)])
    def list_scans() -> list[dict]:
        return [
            {
                "id": s.id,
                "status": s.status.value,
                "source": s.source,
                "findings": s.summary.total_findings,
                "created_at": s.created_at,
            }
            for s in sorted(store.all(), key=lambda s: s.created_at, reverse=True)
        ]

    @app.get("/api/scans/{scan_id}", dependencies=[Depends(require_token)])
    def get_scan(scan_id: str) -> dict:
        scan = store.get(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return scan.model_dump(mode="json")

    @app.get("/api/scans/{scan_id}/report", dependencies=[Depends(require_token)])
    def get_report(scan_id: str, format: str = "json") -> Response:
        scan = store.get(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="scan not found")
        fmt = format.lower()
        if fmt == "json":
            return JSONResponse(content=scan.model_dump(mode="json"))
        if fmt == "sarif":
            return Response(content=to_sarif_str(scan), media_type="application/sarif+json")
        if fmt == "pdf":
            return Response(
                content=to_pdf(scan),
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="codeshield-{scan.id}.pdf"'},
            )
        raise HTTPException(status_code=400, detail="format must be json, sarif or pdf")

    @app.get("/api/scans/{scan_id}/patches/{finding_id}", dependencies=[Depends(require_token)])
    def get_patch(scan_id: str, finding_id: str) -> dict:
        scan = store.get(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="scan not found")
        for patch in scan.patches:
            if patch.finding_id == finding_id:
                return patch.model_dump(mode="json")
        raise HTTPException(status_code=404, detail="no patch for that finding")

    @app.post("/api/scans/{scan_id}/findings/{finding_id}/status", dependencies=[Depends(require_token)])
    def update_status(scan_id: str, finding_id: str, update: StatusUpdate) -> dict:
        scan = store.get(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="scan not found")
        finding = scan.finding(finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="finding not found")
        finding.status = update.status
        return {"id": finding.id, "status": finding.status.value}

    # Dashboard (served last so /api and /health win).
    web_dir = (__import__("pathlib").Path(__file__).resolve().parent.parent / "web")
    if web_dir.is_dir():
        app.mount("/", StaticFiles(directory=str(web_dir), html=True), name="dashboard")

    return app


app = create_app()
