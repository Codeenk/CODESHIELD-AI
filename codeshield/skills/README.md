# CodeShield skills

A **skill** is a small Markdown knowledge pack with YAML front-matter. Skills are loaded on
demand and injected into an agent prompt so the scanner/explainer/repairer has the right
context for a weakness — the same idea as `strix/skills/` in
[usestrix/strix](https://github.com/usestrix/strix), adapted to a *static* analysis product.

```yaml
---
name: cwe-89-sql-injection
description: Detect and fix SQL injection
cwe: CWE-89
owasp: A03:2021
targets: [detection, explanation, repair]
triggers: [execute, query, SELECT, f-string]
---
...guidance body...
```

`codeshield/agents/factory.py` loads these packs, selects up to five relevant ones for a
finding's CWE, and assembles the prompt. Add a new weakness by dropping a Markdown file here —
no code change required.
