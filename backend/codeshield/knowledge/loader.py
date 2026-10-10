"""Loader and index for the vendored security knowledge base.

The knowledge base is data, not code: it is read from
``backend/codeshield/knowledge`` at runtime, so modules can be added or edited
without touching the engine.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Optional

from .. import config
from ..schemas import KnowledgeItem

_FRONTMATTER_KEYS = {"name", "description", "license", "author", "homepage"}


def _parse_frontmatter(text: str) -> dict[str, str]:
    """Parse the leading ``---`` YAML block without a YAML dependency."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    meta: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            break
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        if key not in _FRONTMATTER_KEYS:
            continue
        value = value.strip().strip('"').strip("'")
        meta[key] = value
    return meta


def _first_paragraph(text: str) -> str:
    """Return the first non-heading, non-frontmatter paragraph of a markdown file."""
    body = text
    if body.startswith("---"):
        parts = body.split("---", 2)
        body = parts[2] if len(parts) >= 3 else body
    for block in body.split("\n\n"):
        stripped = block.strip()
        if not stripped or stripped.startswith("#"):
            continue
        return " ".join(stripped.split())[:500]
    return ""


class KnowledgeBase:
    """In-memory index over the vendored knowledge base."""

    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = Path(root) if root else config.KNOWLEDGE_DIR
        self.vuln_dir = self.root / "vulnerabilities"
        self._mapping = self._load_mapping()
        self._skills: dict[str, KnowledgeItem] = {}
        self._items: dict[str, KnowledgeItem] = {}
        self._by_cwe: dict[str, str] = {}
        self._load()

    # -- loading ------------------------------------------------------------
    def _load_mapping(self) -> dict[str, dict[str, str]]:
        path = self.root / "mapping.json"
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        return {}

    def _load(self) -> None:
        for path in sorted(self.root.glob("skill_*.md")):
            meta = _parse_frontmatter(path.read_text(encoding="utf-8"))
            slug = path.stem
            self._skills[slug] = KnowledgeItem(
                slug=slug,
                name=meta.get("name", slug),
                description=meta.get("description", ""),
            )
        if self.vuln_dir.exists():
            for path in sorted(self.vuln_dir.glob("*.md")):
                slug = path.stem
                text = path.read_text(encoding="utf-8")
                meta = _parse_frontmatter(text)
                mapped = self._mapping.get(slug, {})
                item = KnowledgeItem(
                    slug=slug,
                    name=meta.get("name", slug.replace("_", " ")),
                    description=meta.get("description") or _first_paragraph(text),
                    cwe=mapped.get("cwe", ""),
                    cwe_title=mapped.get("cwe_title", ""),
                    owasp=mapped.get("owasp", ""),
                    severity=mapped.get("severity", "medium"),  # type: ignore[arg-type]
                )
                self._items[slug] = item
                if item.cwe:
                    self._by_cwe.setdefault(item.cwe.upper(), slug)

    # -- accessors ----------------------------------------------------------
    @property
    def skills(self) -> dict[str, KnowledgeItem]:
        return dict(self._skills)

    @property
    def vulnerabilities(self) -> dict[str, KnowledgeItem]:
        return dict(self._items)

    def get(self, slug: str) -> Optional[KnowledgeItem]:
        return self._items.get(slug) or self._skills.get(slug)

    def for_cwe(self, cwe: str) -> Optional[KnowledgeItem]:
        slug = self._by_cwe.get((cwe or "").upper())
        return self._items.get(slug) if slug else None

    def for_slug(self, slug: str) -> KnowledgeItem:
        item = self._items.get(slug)
        if item:
            return item
        default = self._mapping.get("__default__", {})
        return KnowledgeItem(
            slug=slug or "unknown",
            name=(slug or "unknown").replace("_", " "),
            cwe=default.get("cwe", "CWE-693"),
            cwe_title=default.get("cwe_title", "Protection Mechanism Failure"),
            owasp=default.get("owasp", ""),
            severity=default.get("severity", "medium"),  # type: ignore[arg-type]
        )

    def map_slug(self, slug: str) -> dict[str, str]:
        """Return the CWE/OWASP/severity mapping for a slug."""
        return dict(self._mapping.get(slug, self._mapping.get("__default__", {})))

    def summary(self) -> dict[str, object]:
        return {
            "skill_count": len(self._skills),
            "vulnerability_count": len(self._items),
            "owasp_categories": sorted(
                {item.owasp for item in self._items.values() if item.owasp}
            ),
        }


@lru_cache(maxsize=1)
def get_knowledge_base() -> KnowledgeBase:
    """Process-wide singleton so the KB is parsed once."""
    return KnowledgeBase()
