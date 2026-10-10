"""Generate, verify, and rank candidate patches for a finding."""
from __future__ import annotations

import logging
from typing import Optional

from .. import config
from ..schemas import CodeUnit, Finding, PatchCandidate
from ..sandbox.verifier import Verifier
from .templates import advisory_patch, apply_templates, unified_diff

log = logging.getLogger("codeshield.repair")

_RANK = {"verified": 2, "partially_verified": 1, "unverified": 0}


class PatchGenerator:
    def __init__(self, verifier: Optional[Verifier] = None) -> None:
        self.verifier = verifier or Verifier()

    def generate(self, finding: Finding, unit: CodeUnit) -> list[PatchCandidate]:
        produced = apply_templates(unit, finding)
        if not produced:
            produced = [advisory_patch(unit, finding)]

        candidates: list[PatchCandidate] = []
        seen: set[str] = set()
        for item in produced:
            source = item["source"]
            if source in seen:
                continue
            seen.add(source)
            report = self.verifier.verify(unit, source, finding)
            status = report.status
            # A behaviour-changing rewrite is never fully "verified" purely by
            # static checks: downgrade it one notch for honesty.
            if item.get("semantic_risk") and status == "verified":
                status = "partially_verified"
            candidates.append(
                PatchCandidate(
                    rank=0,
                    source=source,
                    summary=item.get("summary", "patch"),
                    unified_diff=unified_diff(unit.source, source, unit.path),
                    verification=status,  # type: ignore[arg-type]
                    checks=report.as_dicts(),
                    rationale=item.get("rationale", ""),
                    semantic_risk=bool(item.get("semantic_risk")),
                )
            )

        candidates.sort(
            key=lambda c: (
                -_RANK[c.verification],
                len(c.unified_diff),  # prefer the smallest diff
            )
        )
        for i, cand in enumerate(candidates, start=1):
            cand.rank = i
        return candidates[: config.REPAIR_MAX_CANDIDATES]
