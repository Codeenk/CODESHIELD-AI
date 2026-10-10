"""Agent prompt layer — prompt packs + on-demand skill loading (strix-inspired).

See :mod:`codeshield.agents.factory`.
"""

from __future__ import annotations

from .factory import AGENTS, Skill, build_agent_prompt, load_skills, select_skills, skill_catalog

__all__ = [
    "AGENTS",
    "Skill",
    "build_agent_prompt",
    "load_skills",
    "select_skills",
    "skill_catalog",
]
