# Setup

CodeShield runs with **no models and no Docker**. The optional detector, local
repair model, and container test sandbox are layered on top.

## Prerequisites

| Requirement | Version | Notes |
| --- | --- | --- |
| Python | 3.11+ (3.12 recommended) | PyTorch wheels may not exist for 3.14. |
| Node.js | 20+ | Only needed to build or develop the dashboard. |
| uv | recent | Required by the Make targets; a `pip` path is documented below. |
| Docker | optional | Only for the isolated sandbox and production image. |
| Disk | ~2 GB | Core install; +1.6 GB for both models. |
| RAM | 4 GB+ | CodeBERT + Qwen2.5-Coder 1.5B Q4 fit in ~3 GB. |

## Fast path with Make

```bash
cp .env.example .env
make install          # Python 3.12 venv, core deps, frontend deps
make install-ml       # PyTorch CPU wheel + Transformers
make models           # CodeBERT (~476 MB) + Qwen2.5-Coder GGUF (~1.1 GB)
make llama            # prebuilt llama.cpp CPU server in .tools/
make model-server     # terminal 1: repair endpoint on :8080
make seed             # optional demo scans
make serve            # terminal 2: dashboard on http://127.0.0.1:8000
```

`make install-ml` installs the CPU PyTorch wheel by default. For CUDA, pass the
index for your driver:

```bash
make install-ml TORCH_INDEX=https://download.pytorch.org/whl/cu128
```

## Manual path

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r backend/requirements.txt
uv pip install --python .venv/bin/python torch \
  --index-url https://download.pytorch.org/whl/cpu
uv pip install --python .venv/bin/python -r backend/requirements-ml.txt

cd frontend && npm ci --no-audit --no-fund && npm run build && cd ..

.venv/bin/python backend/scripts/download_models.py --all
.venv/bin/python backend/scripts/seed_demo.py

cd backend && ../.venv/bin/python -m codeshield
```

If you prefer `pip`, create the venv with Python 3.12 and use
`.venv/bin/pip install -r ...` instead.

## Configuration

`.env` at the repository root is loaded automatically (existing environment
variables win). Start from the documented template:

```bash
cp .env.example .env
```

Common local model configuration:

```ini
CODESHIELD_MODEL_MODE=on
CODESHIELD_MODEL_DIR=models/detector
CODESHIELD_REPAIR_PROVIDER=llm
CODESHIELD_LLM_BASE_URL=http://127.0.0.1:8080/v1
CODESHIELD_LLM_MODEL=qwen2.5-coder-1.5b-instruct
CODESHIELD_LLM_TIMEOUT=180
CODESHIELD_LLM_MAX_TOKENS=1200
```

With `CODESHIELD_MODEL_MODE=auto`, a local detector directory is used when
present; otherwise the API reports the model as unavailable and rules continue
to run. `CODESHIELD_MODEL_MODE=on` requires a working detector. Downloads are
disabled by default (`CODESHIELD_ALLOW_MODEL_DOWNLOAD=false`).

## Demo account and data

`seed_demo.py` creates:

| Item | Value |
| --- | --- |
| Email | `demo@codeshield.local` |
| Password | `demo1234` |
| Vulnerable sample | 13 findings across 3 files |
| Clean sample | 0 findings |

Set `CODESHIELD_AUTH=off` for a single-user local session. For CI, a static
`CODESHIELD_API_TOKEN` authenticates as `ci@codeshield.local`.

## Verify the install

```bash
make test             # backend suite
make scan             # self-scan, expected exit 0
make build            # production frontend
curl http://127.0.0.1:8000/api/v1/health
curl http://127.0.0.1:8000/api/v1/meta
```

`/api/v1/meta` reports whether the detector is loaded, the repair provider,
sandbox mode, retention, and configured limits. Model setup, hardware guidance,
and troubleshooting are in [MODELS.md](MODELS.md); sandbox details are in
[SANDBOX.md](SANDBOX.md); deployment is in [OPERATIONS.md](OPERATIONS.md).
