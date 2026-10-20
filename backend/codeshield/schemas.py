"""Pydantic models shared by the pipeline, store, API, and reports."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

import re

from pydantic import BaseModel, Field, field_validator

Severity = Literal["critical", "high", "medium", "low", "info"]
EngineTag = Literal["model", "rules", "both"]
FindingStatus = Literal["open", "fixed", "false_positive", "accepted_risk"]
VerificationStatus = Literal["verified", "partially_verified", "unverified"]
ScanStatus = Literal["queued", "running", "completed", "failed", "cancelled"]
SourceType = Literal["upload", "zip", "repo", "snippet"]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Evidence(BaseModel):
    line: int
    snippet: str
    reason: str
    weight: float = 1.0


class AstNode(BaseModel):
    line: int
    node_type: str
    col: int = 0
    snippet: str = ""
    role: str = "context"


class CodeUnit(BaseModel):
    path: str
    language: str
    name: str
    start_line: int
    end_line: int
    source: str
    container: Optional[str] = None
    signature: str = ""
    kind: str = "function"


class PatchCandidate(BaseModel):
    rank: int = 0
    source: str
    summary: str
    unified_diff: str = ""
    verification: VerificationStatus = "unverified"
    checks: list[dict[str, Any]] = Field(default_factory=list)
    rationale: str = ""
    semantic_risk: bool = False
    generator: str = "template"
    language: str = ""


class Finding(BaseModel):
    id: str
    scan_id: Optional[str] = None
    project_id: Optional[str] = None
    path: str
    language: str
    function: str
    start_line: int
    end_line: int
    cwe: str
    cwe_title: str = ""
    owasp: str = ""
    severity: Severity = "medium"
    confidence: float = 0.0
    engine: EngineTag = "rules"
    message: str = ""
    function_source: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    ast_nodes: list[AstNode] = Field(default_factory=list)
    explanation: Optional[dict[str, Any]] = None
    knowledge_ref: Optional[str] = None
    patch_candidates: list[PatchCandidate] = Field(default_factory=list)
    status: FindingStatus = "open"
    suppressed: bool = False
    fingerprint: str = ""
    created_at: datetime = Field(default_factory=utcnow)

    @field_validator("confidence")
    @classmethod
    def _clamp(cls, v: float) -> float:
        return max(0.0, min(1.0, float(v)))


class ScanSummary(BaseModel):
    total_findings: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_cwe: dict[str, int] = Field(default_factory=dict)
    by_engine: dict[str, int] = Field(default_factory=dict)
    by_file: dict[str, int] = Field(default_factory=dict)
    files_scanned: int = 0
    units_scanned: int = 0
    lines_scanned: int = 0
    languages: list[str] = Field(default_factory=list)
    model_used: bool = False
    model_id: str = ""
    engine_notes: list[str] = Field(default_factory=list)
    errors: list[dict[str, str]] = Field(default_factory=list)
    suppressed: int = 0
    coverage: dict[str, Any] = Field(default_factory=dict)
    duration_ms: int = 0


class Scan(BaseModel):
    id: str
    user_id: Optional[str] = None
    project_id: Optional[str] = None
    project_name: str = ""
    created_at: datetime = Field(default_factory=utcnow)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    target: str
    source_type: SourceType = "upload"
    status: ScanStatus = "queued"
    stage: str = "queued"
    progress: int = 0
    error: Optional[str] = None
    summary: ScanSummary = Field(default_factory=ScanSummary)
    config: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)


class ScanConfig(BaseModel):
    repo_url: Optional[str] = None
    branch: Optional[str] = None
    commit: Optional[str] = None
    project_id: Optional[str] = None
    project_name: Optional[str] = None
    generate_patches: bool = True
    model_mode: Optional[str] = None


class User(BaseModel):
    id: str
    email: str
    name: str
    role: str = "member"
    avatar_url: str = ""
    created_at: datetime = Field(default_factory=utcnow)


class Project(BaseModel):
    id: str
    user_id: str
    name: str
    created_at: datetime = Field(default_factory=utcnow)
    scan_count: int = 0
    last_scan_at: Optional[datetime] = None
    open_findings: int = 0


def _valid_email(value: str) -> str:
    value = value.strip()
    if len(value) > 254 or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value):
        raise ValueError("Enter a valid email address")
    return value


class RegisterRequest(BaseModel):
    email: str
    password: str = Field(min_length=8, max_length=200)
    name: str = Field(min_length=1, max_length=80)

    _email = field_validator("email")(_valid_email)


class LoginRequest(BaseModel):
    email: str
    password: str

    _email = field_validator("email")(_valid_email)


class StatusUpdate(BaseModel):
    status: FindingStatus
    note: str = ""


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)


class KnowledgeItem(BaseModel):
    slug: str
    name: str
    description: str = ""
    cwe: str = ""
    cwe_title: str = ""
    owasp: str = ""
    severity: Severity = "medium"
    kind: str = "vulnerability"


class CompareFinding(BaseModel):
    fingerprint: str
    cwe: str
    cwe_title: str = ""
    severity: Severity
    path: str
    function: str
    line: int
    status: str


class ScanComparison(BaseModel):
    base_scan: str
    head_scan: str
    new: list[CompareFinding] = Field(default_factory=list)
    fixed: list[CompareFinding] = Field(default_factory=list)
    recurring: list[CompareFinding] = Field(default_factory=list)
    resolved: int = 0
    introduced: int = 0
    unchanged: int = 0
