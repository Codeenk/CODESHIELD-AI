from codeshield.agents import AGENTS, build_agent_prompt, load_skills, select_skills, skill_catalog


def test_skills_are_discovered():
    skills = load_skills()
    assert "cwe-89-sql-injection" in skills
    assert skills["cwe-89-sql-injection"].cwe == "CWE-89"


def test_skill_selection_by_cwe_first():
    selected = select_skills(cwe="CWE-78")
    assert selected
    assert selected[0].cwe == "CWE-78"


def test_select_skills_respects_limit():
    assert len(select_skills(text="execute query shell pickle", limit=2)) <= 2


def test_build_agent_prompt_includes_base_and_skills():
    prompt = build_agent_prompt("repairer", cwe="CWE-79")
    assert "CodeShield Repairer" in prompt
    assert "Loaded skills" in prompt
    assert "CWE-79" in prompt


def test_unknown_agent_rejected():
    import pytest

    with pytest.raises(ValueError):
        build_agent_prompt("nope")


def test_catalog_is_serialisable():
    catalog = skill_catalog()
    assert catalog
    assert {"name", "description", "cwe"} <= set(catalog[0])
    assert set(AGENTS) == {"scanner", "explainer", "repairer"}
