"""Domain models for CodeShield AI scans, findings, patches and reports."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


def new_id(prefix: str = "") -> str:
    token = uuid.uuid4().hex[:12]
    return f"{prefix}{token}" if prefix else token


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


class Engine(str, Enum):
    model = "model"
    rules = "rules"
    both = "both"


class PatchStatus(str, Enum):
    verified = "verified"          # parses AND no longer flagged on re-scan
    partial = "partial"            # parses but re-scan inconclusive / residual risk
    unverified = "unverified"      # could not be validated — never shown as safe


class FindingStatus(str, Enum):
    open = "open"
    fixed = "fixed"
    false_positive = "false_positive"
    accepted_risk = "accepted_risk"


class ScanStatus(str, Enum):
    queued = "queued"
    running = "running"
    done = "done"
    error = "error"


class Location(BaseModel):
    file: str
    start_line: int
    end_line: int
    function: str | None = None


class AttentionLine(BaseModel):
    line: int
    score: float


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: new_id("f_"))
    file: str
    location: Location
    cwe: str
    cwe_name: str
    severity: Severity
    confidence: float
    engine: Engine
    title: str
    rationale: str
    exploit: str | None = None
    remediation: str | None = None
    snippet: str = ""
    syntax_nodes: list[str] = Field(default_factory=list)
    attention: list[AttentionLine] = Field(default_factory=list)
    owasp: str | None = None
    status: FindingStatus = FindingStatus.open
    fingerprint: str = ""

    def sort_key(self) -> tuple:
        return (-self.severity.rank, -self.confidence, self.file, self.location.start_line)


class Patch(BaseModel):
    id: str = Field(default_factory=lambda: new_id("p_"))
    finding_id: str
    status: PatchStatus
    summary: str
    original_code: str
    patched_code: str
    diff: str = ""
    verification: list[str] = Field(default_factory=list)
    source: str = "template"  # template | llm
    rank: int = 0


class FileReport(BaseModel):
    path: str
    language: str
    loc: int
    sha256: str
    findings: int = 0
    skipped: bool = False
    skip_reason: str | None = None


class ScanSummary(BaseModel):
    files_scanned: int = 0
    files_skipped: int = 0
    total_findings: int = 0
    by_severity: dict = Field(default_factory=dict)
    by_cwe: dict = Field(default_factory=dict)
    patches_verified: int = 0


class ScanConfig(BaseModel):
    languages: list[str] = Field(default_factory=list)
    model_threshold: float = 0.55
    model_enabled: bool = False
    retain_code: bool = False


class ScanResult(BaseModel):
    id: str = Field(default_factory=lambda: new_id("s_"))
    status: ScanStatus = ScanStatus.queued
    source: str = ""
    created_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    error: str | None = None
    config: ScanConfig = Field(default_factory=ScanConfig)
    files: list[FileReport] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    patches: list[Patch] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    engine_notes: list[str] = Field(default_factory=list)
    model_version: str | None = None
    codeshield_version: str = "0.1.0"

    def finding(self, finding_id: str) -> Finding | None:
        for f in self.findings:
            if f.id == finding_id:
                return f
        return None
