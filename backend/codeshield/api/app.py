"""FastAPI application: scan submission, results, patches, and reports."""
from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.datastructures import UploadFile

from .. import __version__, config
from ..ingestion.loader import IngestionError
from ..knowledge.loader import get_knowledge_base
from ..pipeline import get_pipeline
from ..reporting import reporter
from ..schemas import Scan, StatusUpdate

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("codeshield.api")


def require_token(request: Request) -> None:
    """Bearer-token gate. Disabled entirely when CODESHIELD_API_TOKEN is unset."""
    if not config.API_TOKEN:
        return
    header = request.headers.get("authorization", "")
    if header != f"Bearer {config.API_TOKEN}":
        raise HTTPException(status_code=401, detail="Missing or invalid API token")


router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_token)])


@router.get("/knowledge")
def knowledge() -> dict:
    kb = get_knowledge_base()
    return {
        "summary": kb.summary(),
        "skills": [item.model_dump() for item in kb.skills.values()],
        "vulnerabilities": [item.model_dump() for item in kb.vulnerabilities.values()],
    }


async def _run_scan_from_request(request: Request) -> Scan:
    pipeline = get_pipeline()
    ctype = request.headers.get("content-type", "")
    try:
        if ctype.startswith("multipart/form-data"):
            form = await request.form()
            uploads: list[tuple[str, bytes]] = []
            for _key, value in form.multi_items():
                # Starlette's form parser yields starlette UploadFile objects.
                if isinstance(value, UploadFile):
                    uploads.append((value.filename or "upload", await value.read()))
            if not uploads:
                raise HTTPException(status_code=400, detail="No files were uploaded")
            return pipeline.scan_uploads(uploads, target=", ".join(name for name, _ in uploads)[:120])
        body = await request.json()
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Could not parse request: {exc}") from exc

    if isinstance(body, dict) and body.get("code") is not None:
        filename = body.get("filename", "snippet.py")
        return pipeline.scan_uploads([(filename, body["code"].encode("utf-8"))], target=filename)
    if isinstance(body, dict) and body.get("repo_url"):
        return pipeline.scan_repo(body["repo_url"], body.get("branch"))
    raise HTTPException(status_code=400, detail="Provide uploaded files, inline code, or a repo_url")


@router.post("/scans", response_model=Scan)
async def create_scan(request: Request) -> Scan:
    try:
        return await _run_scan_from_request(request)
    except IngestionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/scans")
def list_scans(limit: int = 50, offset: int = 0) -> dict:
    store = get_pipeline().store
    return {"scans": store.list_scans(limit=limit, offset=offset)}


@router.get("/scans/{scan_id}", response_model=Scan)
def get_scan(scan_id: str) -> Scan:
    scan = get_pipeline().store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: str) -> dict:
    get_pipeline().store.delete_scan(scan_id)
    return {"deleted": scan_id}


@router.get("/scans/{scan_id}/findings")
def get_findings(scan_id: str) -> dict:
    scan = get_pipeline().store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"scan_id": scan_id, "findings": [f.model_dump() for f in scan.findings]}


@router.get("/findings/{finding_id}")
def get_finding(finding_id: str) -> dict:
    result = get_pipeline().store.get_finding(finding_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    _scan_id, finding = result
    return finding.model_dump()


@router.get("/findings/{finding_id}/patches")
def get_patches(finding_id: str) -> dict:
    result = get_pipeline().store.get_finding(finding_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    _scan_id, finding = result
    return {"finding_id": finding_id, "candidates": [c.model_dump() for c in finding.patch_candidates]}


@router.post("/findings/{finding_id}/status")
def set_status(finding_id: str, update: StatusUpdate) -> dict:
    ok = get_pipeline().store.update_finding_status(finding_id, update.status)
    if not ok:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"finding_id": finding_id, "status": update.status}


@router.get("/scans/{scan_id}/report")
def get_report(scan_id: str, format: str = "json") -> Response:  # noqa: A002 - API name
    scan = get_pipeline().store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    fmt = format.lower()
    if fmt == "json":
        return JSONResponse(content={"scan": scan.model_dump(mode="json")})
    if fmt == "sarif":
        return JSONResponse(content=reporter.to_sarif(scan))
    if fmt == "html":
        return HTMLResponse(content=reporter.to_html(scan))
    if fmt == "pdf":
        pdf = reporter.to_pdf(scan)
        return Response(
            content=pdf, media_type="application/pdf",
            headers={"Content-Disposition": f'inline; filename="codeshield-{scan_id}.pdf"'},
        )
    raise HTTPException(status_code=400, detail="format must be json, sarif, html, or pdf")


def create_app() -> FastAPI:
    app = FastAPI(
        title="CodeShield AI",
        version=__version__,
        description="AI-powered source code vulnerability scanner with explainable auto-repair.",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    def health() -> dict[str, Any]:
        pipeline = get_pipeline()
        return {
            "status": "ok",
            "version": __version__,
            "model_mode": config.MODEL_MODE,
            "model_id": config.DETECTION_MODEL_ID,
            "model_loaded": bool(getattr(pipeline.engine.detector, "available", False)),
            "auth_required": bool(config.API_TOKEN),
            "knowledge": get_knowledge_base().summary(),
        }

    app.include_router(router)

    # Serve the built dashboard if it exists; otherwise say how to build it.
    if config.FRONTEND_DIST.exists():
        app.mount("/", StaticFiles(directory=str(config.FRONTEND_DIST), html=True), name="ui")
    else:
        @app.get("/")
        def _index() -> HTMLResponse:
            return HTMLResponse(
                "<h1>CodeShield AI</h1><p>API is running. Build the dashboard with "
                "<code>cd frontend &amp;&amp; npm install &amp;&amp; npm run build</code>, "
                "or open <a href='/docs'>/docs</a>.</p>"
            )

    return app


app = create_app()
