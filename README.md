# CodeShield AI

Precision-first source-code review with explainable findings and verified repairs.

CodeShield scans Python, JavaScript/TypeScript, and Java, shows the exact lines and
functions behind each finding, grounds explanations in a vendored vulnerability
knowledge base, and proposes patches that are re-parsed and re-scanned before they
are shown. Optional CodeBERT detection and LLM repair plug in when models are
available; the product works fully without them.

> Decision support, not certification. Every finding is a review candidate and
> every patch still needs human review.

## What it does

1. **Ingest** — paste a snippet, upload files or a bounded `.zip`, or shallow-clone
   an allowlisted public repository.
2. **Parse** — Python `ast` plus Tree-sitter for JavaScript/TypeScript/Java, with a
   tolerant fallback parser.
3. **Detect** — deterministic AST rules with scoped taint tracking, deduplicated by
   `(path, CWE, line)` and fingerprinted for tracking across scans. Optional
   CodeBERT inference boosts confidence when it agrees with a rule; it never
   creates rule-less findings unless explicitly enabled.
4. **Explain** — evidence lines, rationale, CWE/OWASP mapping, and citations into
   the knowledge base (`backend/codeshield/knowledge/`).
5. **Repair** — language-aware templates plus optional Qwen/OpenAI-compatible
   generation. Each candidate is checked for syntax, remaining findings, new
   high-risk findings, and signature preservation; tests run only when opted in.
6. **Report** — JSON, SARIF 2.1.0, HTML, and PDF; scan history, comparison,
   suppression with fingerprints, and a responsive security console.

Verified locally: the scanner reports **0 findings on its own backend** while
detecting all seeded weaknesses in `samples/vulnerable`.

## Screens

- **Overview** — open exposure, severity mix, trend, top CWEs, recent scans.
- **New scan** — repository, files, archive, or snippet with project grouping.
- **Scan detail** — filterable findings, evidence, source, repair diff, status history.
- **History / Compare** — revision deltas: new, fixed, recurring, resolved.
- **Knowledge** — vulnerability modules plus the live rule catalog.
- **Settings** — runtime, model, sandbox, privacy, and limit status.

## Quick start

Requires Python 3.11+ (3.12 recommended) and Node 20+. The Make targets use
`uv`; the manual `pip` path is in [docs/SETUP.md](docs/SETUP.md).

```bash
cp .env.example .env
make install          # Python 3.12 venv, core deps, frontend deps
make seed             # optional demo scans
make serve            # build frontend, run API on :8000
```

The dashboard is at <http://127.0.0.1:8000>; interactive API docs at
`/docs`. Demo account: `demo@codeshield.local` / `demo1234`. Set
`CODESHIELD_AUTH=off` for a single-user local session.

### Add the optional models

Rules-only scanning works with `make install` alone. For CodeBERT detection and
local LLM repairs:

```bash
make install-ml       # PyTorch CPU wheel + Transformers
make models           # CodeBERT + Qwen2.5-Coder 1.5B GGUF
make llama            # prebuilt llama.cpp CPU server
make model-server     # terminal 1: :8080
make serve            # terminal 2: dashboard
```

Configure the endpoint in `.env`:

```ini
CODESHIELD_MODEL_MODE=on
CODESHIELD_REPAIR_PROVIDER=llm
CODESHIELD_LLM_BASE_URL=http://127.0.0.1:8080/v1
CODESHIELD_LLM_MODEL=qwen2.5-coder-1.5b-instruct
```

See [docs/SETUP.md](docs/SETUP.md) for manual installation,
[docs/MODELS.md](docs/MODELS.md) for hardware guidance and troubleshooting, and
[docs/DEMO.md](docs/DEMO.md) for a full walkthrough.

The Makefile also provides `make dev` (backend + Vite), `make test`,
`make scan`, and `make verify`.

## CLI

```bash
python backend/scripts/run_scan.py samples/vulnerable
python backend/scripts/run_scan.py samples/vulnerable --format sarif --out codeshield.sarif
python backend/scripts/run_scan.py backend/codeshield --fail-on high   # self-scan, exit 0
python backend/scripts/run_scan.py --repo https://github.com/org/app --branch main
```

Exit codes: `0` no findings at/above the gate, `2` findings at/above the gate,
`1` ingestion or runtime error.

## Tests

```bash
cd backend && python -m pytest -q
```

The suite covers detection precision (including the self-scan), parser behavior,
guarded/tainted data flow, patch verification, reporting, the REST API, and auth.
CI runs the same suite plus a self-scan and a production frontend build.

## API

All routes are under `/api/v1` unless noted.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Liveness and database status |
| GET | `/meta` | Model, repair, sandbox, privacy, and limit capabilities |
| GET | `/knowledge`, `/knowledge/{slug}` | Modules, rule catalog, and summary |
| POST | `/scans` | Create a scan (multipart: `source_type`, `files`, `repo_url`, `code`, …) |
| GET | `/scans`, `/scans/{id}` | List / fetch scans with findings |
| POST | `/scans/{id}/cancel` · DELETE `/scans/{id}` | Cancel or delete |
| GET | `/scans/compare?base=&head=` | New, fixed, recurring, resolved findings |
| GET | `/scans/{id}/report?format=json\|sarif\|html\|pdf` | Export (`&download=1` to attach) |
| GET / PATCH | `/findings/{id}` | Fetch or update status (`open`, `fixed`, `false_positive`, `accepted_risk`) |
| GET | `/findings/{id}/events` | Status audit trail |
| GET | `/projects`, `/stats` | Grouping and dashboard metrics |
| POST | `/auth/register`, `/auth/login`, `/auth/logout` | Local accounts |
| GET | `/auth/me` | Current user and capability flags |
| GET | `/auth/github`, `/auth/github/callback` | Optional GitHub OAuth |

Authentication uses opaque hashed session tokens in HttpOnly cookies (or
`Authorization: Bearer <CODESHIELD_API_TOKEN>` in CI). Passwords use `scrypt`.
With `CODESHIELD_AUTH=off`, requests run as the local demo analyst.

## Architecture

```
backend/codeshield/
  ingestion/   bounded zip, upload, snippet, and validated git clones
  parsing/     Python AST + Tree-sitter units with tolerant fallbacks
  detection/   rules + scoped taint + optional CodeBERT fusion
  explain/     KB-grounded explanations
  repair/      templates, optional LLM, verification
  sandbox/     static verification + optional isolated test runs
  reporting/   JSON / SARIF / HTML / PDF
  api/         FastAPI routers and SPA hosting
  store.py     SQLite (WAL) projects, scans, findings, suppressions, events
  pipeline.py  ingest → parse → detect → explain → repair → finalize
frontend/      React 18 + Vite + React Router (HashRouter)
samples/       vulnerable and clean demo corpus
docker/        multi-stage production image + compose
.github/       CI, reusable scan action, SARIF upload
```

SQLite and an in-process worker pool keep deployment simple. Run a single server
process because jobs are in-process; the database remains durable across restarts
and stale running scans are marked interrupted on startup.

## Privacy and safety

- Full function bodies are **discarded** unless `CODESHIELD_RETAIN_CODE=true`; the
  UI shows retained evidence snippets and patch diffs instead.
- `CODESHIELD_MASK_SECRETS=true` masks credentials before persistence and export.
- Uploaded code is never executed by default. Test execution is opt-in
  (`CODESHIELD_RUN_TESTS=true`), bounded by timeout and, when available, a container.
- Archives are entry/size/ratio limited; repository clones are HTTPS-only,
  host-allowlisted, depth-1, and read-only.
- Security headers include a strict CSP, `nosniff`, `DENY` framing, and a
  no-referrer policy.

## Configuration

See [.env.example](.env.example) for the full list. Common values:

| Variable | Default | Meaning |
| --- | --- | --- |
| `CODESHIELD_AUTH` | `on` | `on` local accounts (+ optional OAuth) · `off` single user |
| `CODESHIELD_MODEL_MODE` | `auto` | `off` rules-only · `auto` use local weights · `on` require model |
| `CODESHIELD_MODEL_DIR` | `models/detector` | Local CodeBERT directory |
| `CODESHIELD_MODEL_ONLY` | `false` | Emit standalone model-only findings (off for precision) |
| `CODESHIELD_REPAIR_PROVIDER` | `auto` | `none` templates only · `llm` configured endpoint |
| `CODESHIELD_LLM_BASE_URL` | unset | OpenAI-compatible repair endpoint, e.g. local llama.cpp |
| `CODESHIELD_RUN_TESTS` | `false` | Execute project tests during patch verification |
| `CODESHIELD_SANDBOX` | `auto` | `auto` Docker→subprocess · `docker` · `subprocess` · `off` |
| `CODESHIELD_RETAIN_CODE` | `false` | Persist full function bodies |
| `CODESHIELD_DATA_DIR` / `CODESHIELD_DB` | `backend/data` | Storage location |
| `CODESHIELD_API_TOKEN` | unset | Static CI bearer token |

`.env` is loaded automatically; existing environment variables take precedence.
Without local weights and with downloads disabled, the detector reports itself
unavailable and rules continue to run. Full reference: [.env.example](.env.example).

## Docker

```bash
docker build -f docker/Dockerfile -t codeshield:latest .
docker run --rm -p 8000:8000 codeshield:latest
# or
docker compose -f docker/docker-compose.yml up --build
```

The image builds the frontend in a Node stage, runs the API as a non-root user,
serves the dashboard from the same origin, and exposes a health check.

## CI

`.github/workflows/tests.yml` runs pytest, a clean self-scan, and the frontend
build. `.github/workflows/codeshield.yml` demonstrates the reusable
`.github/actions/codeshield-scan` action and uploads SARIF to code scanning.

## Attribution

The vulnerability knowledge base under `backend/codeshield/knowledge/` is derived
from [usestrix/strix](https://github.com/usestrix/strix) (Apache-2.0,
© 2025 OmniSecure Inc.); the full licence is preserved in
[ATTRIBUTION_STRIX_APACHE2_LICENSE.txt](ATTRIBUTION_STRIX_APACHE2_LICENSE.txt).
The optional detector builds on
`mrm8488/codebert-base-finetuned-detect-insecure-code` and `microsoft/codebert-base`.
See [docs/CodeShield_AI_PRD.md](docs/CodeShield_AI_PRD.md) for the product
requirements and measured-model caveats.

## Documentation

- [Setup](docs/SETUP.md) — install, configure, run, verify
- [Models](docs/MODELS.md) — CodeBERT, local repair LLM, hardware and troubleshooting
- [Sandbox](docs/SANDBOX.md) — Docker and subprocess test execution
- [Operations](docs/OPERATIONS.md) — deployment, auth, backups, privacy, limits
- [Demo](docs/DEMO.md) — end-to-end walkthrough and expected results
