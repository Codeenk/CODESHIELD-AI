from conftest import make_unit

from codeshield.detection.engine import build_findings
from codeshield.repair.llm import _extract_json, _from_payload


def test_fenced_json_with_raw_newlines_is_recovered():
    text = '''```json
    {
      "fixes": [
        {
          "source": """
def ping(host):
    return host
""",
          "summary": "keep host",
          "rationale": "no shell",
          "semantic_risk": false
        }
      ]
    }
    ```'''
    payload = _extract_json(text)
    assert isinstance(payload, dict)
    assert payload["fixes"][0]["summary"] == "keep host"


def test_triple_quoted_fix_list_is_accepted_and_dedented():
    unit = make_unit('def ping(host):\n    os.system("ping " + host)')
    finding = build_findings([unit], enable_model=False).findings[0]
    payload = _extract_json(
        '```json\n[{"source":"""\n    def ping(host):\n        return host\n""",'
        '"summary":"no command","rationale":"returns input","semantic_risk":false}]\n```'
    )
    fixes = _from_payload(payload, finding, unit)
    assert len(fixes) == 1
    assert fixes[0].source.startswith("def ping(host):")
    compile(fixes[0].source, "<fix>", "exec")
