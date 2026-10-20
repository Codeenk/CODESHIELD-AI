"""FastAPI application: API routers, security headers, and SPA hosting."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .. import auth, config, db, jobs, store
from . import auth_routes, meta_routes, scan_routes

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("codeshield")


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init_db()
    auth.ensure_demo_user()
    interrupted = store.mark_stale_scans()
    if interrupted:
        log.warning("marked %s interrupted scans after restart", interrupted)
    log.info("%s %s ready on %s:%s", config.APP_NAME, config.VERSION, config.HOST, config.PORT)
    yield
    jobs.shutdown()


app = FastAPI(
    title=config.APP_NAME,
    version=config.VERSION,
    description="Precision-first secure code review with explainable findings and verified repairs.",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url=None,
)
app.add_middleware(GZipMiddleware, minimum_size=1024)
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    path = request.url.path
    if not path.startswith(("/docs", "/openapi.json")):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';"
            " img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self';"
            " worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        )
    if config.COOKIE_SECURE:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


app.include_router(auth_routes.router)
app.include_router(scan_routes.router)
app.include_router(meta_routes.router)


def _dist() -> Path:
    return config.FRONTEND_DIST


_assets = _dist() / "assets"
if _assets.is_dir():
    app.mount("/assets", StaticFiles(directory=_assets), name="assets")


@app.get("/", include_in_schema=False)
def index():
    target = _dist() / "index.html"
    if target.exists():
        return FileResponse(target, headers={"Cache-Control": "no-cache"})
    return JSONResponse(
        {
            "app": config.APP_NAME, "version": config.VERSION,
            "message": "Frontend build not found. Run `make build` or use the Vite dev server.",
            "docs": "/docs", "health": "/api/v1/health",
        }
    )


@app.get("/{full_path:path}", include_in_schema=False)
def spa(full_path: str):
    if full_path.startswith(("api/", "docs", "openapi.json")):
        return JSONResponse({"detail": "Not found"}, status_code=404)
    candidate = _dist() / full_path
    if candidate.is_file() and _dist() in candidate.resolve().parents:
        return FileResponse(candidate)
    target = _dist() / "index.html"
    if target.exists():
        return FileResponse(target, headers={"Cache-Control": "no-cache"})
    return JSONResponse({"detail": "Not found"}, status_code=404)
