"""Generate, verify, and rank repair candidates."""
from __future__ import annotations

from typing import Optional

from .. import config
from ..detection.rules import RuleHit
from ..sandbox.runner import TestRunner
from ..sandbox.verifier import rank, verify_candidate
from ..schemas import CodeUnit, Finding, PatchCandidate
from . import llm
from .templates import TemplateFix, templates_for


def build_patches(
    finding: Finding, unit: Optional[CodeUnit],
    original_hits: Optional[list[RuleHit]] = None,
    runner: Optional[TestRunner] = None,
    allow_llm: bool = True,
) -> list[PatchCandidate]:
    if unit is None:
        return []
    fixes: list[TemplateFix] = list(templates_for(finding, unit))
    if allow_llm and llm.available() and len(fixes) < config.REPAIR_MAX_CANDIDATES:
        remaining = max(1, config.REPAIR_MAX_CANDIDATES - len(fixes))
        fixes.extend(llm.generate(finding, unit, remaining))
    unique: dict[str, TemplateFix] = {}
    for fix in fixes:
        unique.setdefault(fix.source, fix)
    candidates = [
        verify_candidate(finding, unit, fix, original_hits, runner)
        for fix in unique.values()
    ]
    candidates = [candidate for candidate in candidates if candidate.source.strip()]
    return rank(candidates)[: config.REPAIR_MAX_CANDIDATES]


def apply_retention(candidate: PatchCandidate) -> None:
    if not config.RETAIN_CODE:
        candidate.source = ""
    if config.MASK_SECRETS:
        from ..privacy import mask_text

        candidate.unified_diff = mask_text(candidate.unified_diff)
