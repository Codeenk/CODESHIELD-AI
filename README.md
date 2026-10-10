# CodeShield AI

**AI-powered source-code vulnerability scanner & explainable auto-repair engine.**

CodeShield AI scans source code, pinpoints the exact lines *and* syntax nodes behind each finding,
explains the flaw with a CWE reference, and proposes a **verified** patch you can review and accept.
Detection combines a fine-tuned **CodeBERT** classifier with a rule-based baseline; repair generates
candidate patches and re-scans them before presenting anything as safe.

This repository is the **reference implementation of the PRD shipped inside it** — see [PRD.md](PRD.md).
Its asset layout (agent skills, sandbox, SARIF reporting, CI usage) was adapted from the reference
project [usestrix/strix](https://github.com/usestrix/strix), and its detection model is
[`mrm8488/codebert-base-finetuned-detect-insecure-code`](https://huggingface.co/mrm8488/codebert-base-finetuned-detect-insecure-code).

---

## Why it is different

| Problem with today's tools | CodeShield AI |
| --- | --- |
| **Noisy** — rule engines flood you with false positives | Hybrid detection: CodeBERT + rules, agreement raises confidence, disagreement is flagged |
| **Opaque** — a bare risk score | Line-level attention heat-map + attributed AST nodes + plain-English CWE rationale |
| **Unactionable** — detect but do not fix | Patch generation that is **re-scanned (and optionally unit-tested) before it is shown** |

---

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 1. Scan a file or a public GitHub repo from the CLI
python -m codeshield scan examples/vulnerable --format table
python -m codeshield scan https://github.com/psf/requests

# 2. Or run the web app + REST API + dashboard
python -m codeshield serve            # http://127.0.0.1:8000
```

The MVP runs **without a GPU**: the rule-based baseline works out of the box, and the CodeBERT
detector is loaded lazily the first time `torch`/`transformers` are available and the model can be
fetched. When the detector is unavailable the pipeline degrades gracefully and records the reason in
`ScanResult.engine_notes` — it never silently pretends the model ran.

### Optional: enable the neural detector

```bash
pip install -r requirements-ml.txt      # torch + transformers (~476 MB model, CPU is fine)
python -m codeshield scan examples/vulnerable          # model on by default once installed
python scripts/eval_model.py                           # measured precision/recall smoke check
```

The checkpoint is downloaded from the Hub on first use. When it runs, findings two engines agree
on are labelled `both` and get a confidence boost; a model hit with **no** rule support is capped
at **medium** severity and marked *unconfirmed*.

#### Measured reality (20-sample smoke set)

The shipped checkpoint is **not discriminative on its own**, so it is never trusted alone:

| Detector | Precision | Recall | F1 | Accuracy | MCC |
| --- | --- | --- | --- | --- | --- |
| CodeBERT checkpoint alone | 0.50 | 0.90 | 0.643 | 0.50 | **0.00** |
| Rule-based baseline | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |

It scored 9/10 *clean* functions as insecure at ≈0.99. That is a 20-sample smoke set, not the
project-disjoint benchmark PRD §8.1 asks for — see [docs/TRACEABILITY.md](docs/TRACEABILITY.md)
for the full read and the follow-up work.

---

## Project layout

```
codeshield/
  api/            FastAPI app: scan, poll, results, patch, reports, health
  agents/         strix-inspired agent prompt packs (scanner / explainer / repairer)
  core/           the six-stage pipeline
    ingestion.py    upload + GitHub clone, language detection, vendored/binary filtering
    parsing.py      Tree-sitter AST (regex fallback), function extraction, line maps, chunking
    rules.py        rule-based baseline (the precision-first cross-check)
    detection.py    CodeBERT classifier + rule engine + ensemble merge
    explainability.py attention rollup -> lines -> AST nodes + rationale text
    severity.py     CWE -> severity / category / OWASP mapping
    repair.py       candidate patch generation + ranking
    verify.py       parse / re-scan verification, sandboxed test hooks
    scan.py         orchestrator that ties the six stages together
  report/         JSON, SARIF 2.1.0 and PDF report writers
  skills/         strix-inspired CWE knowledge packs (markdown + YAML frontmatter)
  web/            static dashboard (Monaco side-by-side diff) served by the API
  cli.py          `codeshield scan` / `codeshield serve` / `codeshield report`
tests/            pytest suite (runs with zero heavy dependencies)
examples/         intentionally vulnerable sample files
.github/workflows CI + the CodeShield PR scan workflow
action.yml        GitHub Action wrapping the CLI (adapted from the strix CI usage)
```

## REST API (summary)

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/scans` | Submit a file/zip upload (multipart `file`) |
| `POST` | `/api/scans/github` | Submit a public GitHub repo URL |
| `GET`  | `/api/scans/{id}` | Poll status / fetch results |
| `GET`  | `/api/scans/{id}/report?format=json\|sarif\|pdf` | Download a report |
| `GET`  | `/api/scans/{id}/patches/{finding_id}` | Fetch a finding's best patch |
| `GET`  | `/health` | Liveness + which engines are active |

Auth: set `CODESHIELD_API_TOKEN` to require `Authorization: Bearer <token>` (FR-31).

## Non-negotiables (from the PRD)

- Uploaded/cloned code is processed **out of process**; execution for patch validation is intended
  for the sandbox container only ([`docker/`](docker)).
- Code is **not retained** by default — only findings metadata and content hashes (see
  `CODESHIELD_RETAIN_CODE`).
- Secrets found in code are **masked** in the UI and reports.

## Development

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest -q          # 45 tests, rules-only, no GPU or network needed
ruff check codeshield tests
```

### Self-scan baseline (false-positive memory, FR-14)

Because CodeShield flags its own rule definitions and the (escaped) dashboard HTML, the repo
ships a **fingerprint baseline** so CI only fails on *new* issues:

```bash
# re-baseline after an intentional change
python -m codeshield scan codeshield --no-model --write-suppress .codeshield-suppress.txt
# gate (used by .github/workflows/codeshield-scan.yml)
python -m codeshield scan codeshield --no-model --suppress .codeshield-suppress.txt --fail-on high
```

See [docs/TRACEABILITY.md](docs/TRACEABILITY.md) for the requirement-by-requirement map of this
PRD to the code, including the items that are partial or deferred.

## License

MIT — see [LICENSE](LICENSE).
