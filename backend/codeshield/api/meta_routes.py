"""Health, capability, and knowledge-base endpoints."""
from __future__ import annotations

import json
import re

from fastapi import APIRouter, HTTPException

from .. import config, db
from ..detection import model as detector_model
from ..detection.engine import catalog
from ..knowledge.loader import get_knowledge_base

router = APIRouter(prefix="/api/v1", tags=["meta"])
_SLUG = re.compile(r"^[a-z0-9_]{1,80}$")


@router.get("/health")
def health() -> dict:
    try:
        with db.session() as conn:
            conn.execute("SELECT 1").fetchone()
        database = "ok"
    except Exception:
        database = "error"
    return {"status": "ok" if database == "ok" else "degraded", "version": config.VERSION, "database": database}


@router.get("/meta")
def meta() -> dict:
    status = detector_model.status()
    return {
        "app": config.APP_NAME,
        "version": config.VERSION,
        "auth_enabled": config.AUTH_MODE != "off",
        "oauth_enabled": bool(config.GITHUB_CLIENT_ID and config.GITHUB_CLIENT_SECRET),
        "model": {
            "used": bool_status(status),
            "mode": config.MODEL_MODE,
            "id": status.get("model_id", "") if status.get("available") else "",
            "reason": status.get("reason", ""),
            "download_allowed": config.ALLOW_MODEL_DOWNLOAD,
        },
        "repair": {
            "provider": config.REPAIR_PROVIDER,
            "model": config.REPAIR_MODEL_ID or config.LLM_MODEL,
            "max_candidates": config.REPAIR_MAX_CANDIDATES,
        },
        "sandbox": {
            "mode": config.SANDBOX_MODE,
            "tests_enabled": config.RUN_TESTS,
            "image": config.SANDBOX_IMAGE,
        },
        "privacy": {
            "retain_code": config.RETAIN_CODE,
            "mask_secrets": config.MASK_SECRETS,
        },
        "limits": {
            "max_file_bytes": config.MAX_FILE_BYTES,
            "max_archive_bytes": config.MAX_ARCHIVE_BYTES,
            "max_total_bytes": config.MAX_TOTAL_BYTES,
            "max_files": config.MAX_FILES,
            "max_active_scans": config.MAX_ACTIVE_SCANS,
        },
        "capabilities": {
            "languages": ["python", "javascript", "typescript", "tsx", "java"],
            "reports": ["json", "sarif", "html", "pdf"],
            "rules": len(catalog()),
            "knowledge_modules": len(get_knowledge_base().vulnerabilities),
        },
    }


def bool_status(status: dict) -> bool:
    return bool(status.get("available")) and bool(status.get("enabled", True))


@router.get("/knowledge")
def knowledge() -> dict:
    kb = get_knowledge_base()
    items = [
        {
            "slug": item.slug, "name": item.name, "description": item.description,
            "cwe": item.cwe, "cwe_title": item.cwe_title, "owasp": item.owasp,
            "severity": item.severity,
        }
        for item in sorted(kb.vulnerabilities.values(), key=lambda i: (i.cwe, i.slug))
    ]
    return {
        "items": items,
        "rules": catalog(),
        "summary": kb.summary(),
    }


@router.get("/knowledge/{slug}")
def knowledge_item(slug: str) -> dict:
    if not _SLUG.match(slug):
        raise HTTPException(status_code=404, detail="Knowledge entry not found")
    kb = get_knowledge_base()
    item = kb.vulnerabilities.get(slug)
    if not item:
        raise HTTPException(status_code=404, detail="Knowledge entry not found")
    path = kb.vuln_dir / f"{slug}.md"
    body = path.read_text(encoding="utf-8") if path.exists() else ""
    if body.startswith("---"):
        parts = body.split("---", 2)
        body = parts[2] if len(parts) == 3 else body
    remediation_path = config.KNOWLEDGE_DIR / "remediations.json"
    remediation = {}
    if remediation_path.exists():
        try:
            remediation = json.loads(remediation_path.read_text(encoding="utf-8")).get(slug, {})
        except json.JSONDecodeError:
            remediation = {}
    return {
        "slug": item.slug, "name": item.name, "description": item.description,
        "cwe": item.cwe, "cwe_title": item.cwe_title, "owasp": item.owasp,
        "severity": item.severity, "markdown": body.strip(),
        "attack": remediation.get("attack", ""),
        "remediation": remediation.get("remediation", []),
        "references": remediation.get("references", []),
    }
