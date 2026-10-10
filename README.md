# 🛡️ CodeShield AI

AI-powered source-code vulnerability scanner with **explainable auto-repair**.
Scans Python, JavaScript/TypeScript, and Java; explains each finding at line and
AST-node level; and proposes a **verified** patch a developer can accept.

> MVP status. See [docs/CodeShield_AI_PRD.md](docs/CodeShield_AI_PRD.md) for the full product requirements.

## What it does

1. **Ingest** — paste code, upload files/`.zip`, or point at a GitHub repo (shallow, read-only clone).
2. **Parse** — function-level units via Python's `ast` and Tree-sitter for JS/TS/Java.
3. **Detect** — a transparent rule engine plus an optional CodeBERT classifier
   (`mrm8488/codebert-base-finetuned-detect-insecure-code`). Rule + model agreement raises confidence.
4. **Explain** — line evidence, AST nodes, and a rationale grounded in the vendored
   vulnerability knowledge base (29 modules), mapped to CWE and OWASP Top 10:2025.
5. **Repair** — per-flaw patch templates (and a safe advisory fallback), each
   **verified** by re-parsing and re-scanning before it is shown.
6. **Report** — JSON, SARIF 2.1.0, HTML, and PDF; scan history with finding lifecycle.

## Layout

```
backend/codeshield/
  ingestion/  parsing/  detection/  explain/  repair/
  sandbox/    reporting/ store/     api/      knowledge/   # vendored Strix KB (Apache-2.0)
backend/scripts/run_scan.py        # CLI
backend/tests/                     # pytest suite
frontend/                          # React + Vite + Monaco dashboard
samples/{vulnerable,clean}/        # demo corpus
docker/                            # Dockerfile + compose
.github/                           # CI + reusable scan action
```

## Quick start

### Backend

```bash
cd backend
pip install -r requirements.txt          # core
pip install -r requirements-ml.txt       # optional: CodeBERT detector
python -m pytest -q                      # run tests
python -m codeshield                     # serve on http://127.0.0.1:8000
```

Interactive API docs: <http://127.0.0.1:8000/docs>.

### Frontend

```bash
cd frontend
npm install
npm run dev        # dev server on :5173, proxies /api to :8000
npm run build      # builds dist/, which the backend serves at /
```

### Docker

```bash
docker build -f docker/Dockerfile -t codeshield .
docker run --rm -p 8000:8000 codeshield
# or: docker compose -f docker/docker-compose.yml up --build
```

## Command line

```bash
cd backend
python scripts/run_scan.py ../samples/vulnerable          # text report, exit 2 if high+
python scripts/run_scan.py ../samples/clean --fail-on high
python scripts/run_scan.py --repo https://github.com/org/app --format sarif --out out.sarif
```

Exit codes: `0` no findings at/above the gate, `2` findings at/above the gate, `1` error.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Status + knowledge-base counts |
| GET | `/api/v1/knowledge` | Skill and vulnerability modules |
| POST | `/api/v1/scans` | Scan uploads (multipart), inline `{code,filename}`, or `{repo_url,branch}` |
| GET | `/api/v1/scans` · `/api/v1/scans/{id}` | List / fetch scans |
| GET | `/api/v1/scans/{id}/findings` · `/api/v1/findings/{id}` | Findings |
| GET | `/api/v1/findings/{id}/patches` | Verified patch candidates |
| POST | `/api/v1/findings/{id}/status` | `open` / `fixed` / `false_positive` / `accepted_risk` |
| GET | `/api/v1/scans/{id}/report?format=json\|sarif\|html\|pdf` | Reports |

## Configuration (environment)

| Variable | Default | Meaning |
| --- | --- | --- |
| `CODESHIELD_MODEL_MODE` | `auto` | `off` rules-only · `auto` use model if available · `on` require model |
| `CODESHIELD_MODEL` | `mrm8488/codebert-base-finetuned-detect-insecure-code` | Detection checkpoint |
| `CODESHIELD_MODEL_ONLY` | `0` | Emit standalone model-only findings. Off by default — the binary checkpoint flags most code, so it corroborates rather than detects. |
| `CODESHIELD_API_TOKEN` | *(unset)* | When set, require `Authorization: Bearer <token>` on `/api/v1` |
| `CODESHIELD_HOST` / `CODESHIELD_PORT` | `127.0.0.1` / `8000` | Server bind |
| `CODESHIELD_DB` | `backend/data/codeshield.db` | SQLite location |
| `CODESHIELD_RUN_TESTS` | `0` | Opt in to executing a project's pytest inside the sandbox |
| `CODESHIELD_MAX_FILE_BYTES` / `..._ARCHIVE_BYTES` | 5 MB / 50 MB | Ingestion limits |

## Security model

Ingested code is **never executed** by default. Patch verification is static
(parse + re-scan); test execution is opt-in (`CODESHIELD_RUN_TESTS=1`) and runs in a
throwaway temp directory. The scanner is decision support, not a certification —
read the confidence, engine tag, and verification status on every finding.

## Attribution

The vulnerability knowledge base under `backend/codeshield/knowledge/` is derived
from [usestrix/strix](https://github.com/usestrix/strix) (Apache-2.0,
© 2025 OmniSecure Inc.); the full licence is preserved in
[ATTRIBUTION_STRIX_APACHE2_LICENSE.txt](ATTRIBUTION_STRIX_APACHE2_LICENSE.txt).
Detection uses `mrm8488/codebert-base-finetuned-detect-insecure-code`, built on
`microsoft/codebert-base`.
