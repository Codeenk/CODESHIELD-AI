"""Pydantic schemas shared across the CodeShield pipeline and API."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator

Severity = Literal["critical", "high", "medium", "low", "info"]
EngineTag = Literal["model", "rules", "both"]
FindingStatus = Literal["open", "fixed", "false_positive", "accepted_risk"]
VerificationStatus = Literal["verified", "partially_verified", "unverified"]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Evidence(BaseModel):
    """A single line that supports (or explains) a finding."""

    line: int
    snippet: str
    reason: str
    weight: float = 1.0


class CodeUnit(BaseModel):
    """A function/method-level unit of code that detection operates on."""

    path: str
    language: str
    name: str
    start_line: int
    end_line: int
    source: str
    container: Optional[str] = None


class PatchCandidate(BaseModel):
    rank: int
    source: str
    summary: str
    unified_diff: str = ""
    verification: VerificationStatus = "unverified"
    checks: list[dict[str, Any]] = Field(default_factory=list)
    rationale: str = ""
    semantic_risk: bool = False


class Finding(BaseModel):
    id: str
    scan_id: Optional[str] = None
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
    explanation: Optional[dict[str, Any]] = None
    knowledge_ref: Optional[str] = None
    patch_candidates: list[PatchCandidate] = Field(default_factory=list)
    status: FindingStatus = "open"
    fingerprint: str = ""

    @field_validator("confidence")
    @classmethod
    def _clamp(cls, v: float) -> float:
        return max(0.0, min(1.0, float(v)))


class ScanSummary(BaseModel):
    total_findings: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_cwe: dict[str, int] = Field(default_factory=dict)
    by_engine: dict[str, int] = Field(default_factory=dict)
    files_scanned: int = 0
    units_scanned: int = 0
    languages: list[str] = Field(default_factory=list)
    model_used: bool = False
    coverage: dict[str, Any] = Field(default_factory=dict)


class Scan(BaseModel):
    id: str
    created_at: datetime = Field(default_factory=utcnow)
    target: str
    source_type: Literal["upload", "repo", "zip"]
    status: Literal["pending", "running", "completed", "failed"] = "pending"
    error: Optional[str] = None
    summary: ScanSummary = Field(default_factory=ScanSummary)
    config: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)


class ScanRequest(BaseModel):
    repo_url: Optional[str] = None
    branch: Optional[str] = None


class StatusUpdate(BaseModel):
    status: FindingStatus


class KnowledgeItem(BaseModel):
    slug: str
    name: str
    description: str = ""
    cwe: str = ""
    cwe_title: str = ""
    owasp: str = ""
    severity: Severity = "medium"
