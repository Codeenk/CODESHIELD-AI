"""Agent factory (adapted from ``strix/agents/factory.py`` + ``prompt.py``).

The three agents in CodeShield — **scanner**, **explainer**, **repairer** — each get a base
prompt plus up to *five* relevant skills selected for the weakness under analysis. This mirrors
how strix assembles an agent prompt from prompt packs and dynamically loaded skills, but here
it feeds a deterministic static-analysis pipeline rather than an autonomous pentester.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

try:  # PyYAML is a core dependency; keep a fallback for robustness.
    import yaml
except Exception:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = PACKAGE_ROOT / "skills"
PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"

AGENTS = ("scanner", "explainer", "repairer")
MAX_SKILLS = 5


@dataclass
class Skill:
    name: str
    description: str
    cwe: str = ""
    owasp: str = ""
    targets: tuple[str, ...] = ()
    triggers: tuple[str, ...] = ()
    body: str = ""
    path: str = ""

    def matches(self, cwe: str | None, target: str | None, text: str = "") -> int:
        score = 0
        if cwe and self.cwe and cwe.upper() == self.cwe.upper():
            score += 10
        if target and target in self.targets:
            score += 2
        lowered = text.lower()
        score += sum(1 for trigger in self.triggers if trigger.lower() in lowered)
        return score


def _split_frontmatter(text: str) -> tuple[dict, str]:
    if not text.startswith("---"):
        return {}, text
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}, text
    header, body = parts[1], parts[2]
    if yaml is not None:
        data = yaml.safe_load(header) or {}
    else:  # pragma: no cover - minimal fallback parser
        data = {}
        for line in header.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                data[key.strip()] = value.strip()
    return data, body.strip()


_SKILL_CACHE: dict[str, Skill] | None = None


def load_skills(force: bool = False) -> dict[str, Skill]:
    global _SKILL_CACHE
    if _SKILL_CACHE is not None and not force:
        return _SKILL_CACHE

    skills: dict[str, Skill] = {}
    if SKILLS_DIR.is_dir():
        for path in sorted(SKILLS_DIR.glob("*.md")):
            if path.name.lower() == "readme.md":
                continue
            text = path.read_text(encoding="utf-8")
            meta, body = _split_frontmatter(text)
            name = meta.get("name") or path.stem
            skills[name] = Skill(
                name=name,
                description=meta.get("description", ""),
                cwe=str(meta.get("cwe", "")),
                owasp=str(meta.get("owasp", "")),
                targets=tuple(meta.get("targets", []) or []),
                triggers=tuple(meta.get("triggers", []) or []),
                body=body,
                path=str(path.relative_to(PACKAGE_ROOT)),
            )
    _SKILL_CACHE = skills
    return skills


def select_skills(
    cwe: str | None = None, target: str | None = None, text: str = "", limit: int = MAX_SKILLS
) -> list[Skill]:
    scored = [
        (skill.matches(cwe, target, text), skill) for skill in load_skills().values()
    ]
    scored = [(score, skill) for score, skill in scored if score > 0]
    scored.sort(key=lambda pair: (-pair[0], pair[1].name))
    return [skill for _score, skill in scored[:limit]]


def load_prompt(agent: str) -> str:
    path = PROMPTS_DIR / f"{agent}.md"
    if not path.is_file():
        raise ValueError(f"unknown agent prompt: {agent}")
    return path.read_text(encoding="utf-8").strip()


def build_agent_prompt(
    agent: str,
    cwe: str | None = None,
    text: str = "",
    skills: Iterable[Skill] | None = None,
    limit_skills: int = MAX_SKILLS,
) -> str:
    """Assemble the agent prompt + up to ``limit_skills`` relevant knowledge packs."""
    if agent not in AGENTS:
        raise ValueError(f"unknown agent: {agent}")
    base = load_prompt(agent)
    chosen = list(skills) if skills is not None else select_skills(cwe, agent, text, limit_skills)
    if not chosen:
        return base
    blocks = "\n\n".join(f"## Skill: {skill.name}\n{skill.body}" for skill in chosen)
    return f"{base}\n\n# Loaded skills ({len(chosen)})\n\n{blocks}"


def skill_catalog() -> list[dict]:
    """Machine-readable skill list for the API/dashboard."""
    return [
        {
            "name": skill.name,
            "description": skill.description,
            "cwe": skill.cwe,
            "owasp": skill.owasp,
            "targets": list(skill.targets),
            "path": skill.path,
        }
        for skill in load_skills().values()
    ]
