# Local models

Both models are optional. Rules-only mode is the default; the API degrades
gracefully when weights or the repair endpoint are missing.

## What the two models do

| Model | Role | Default location | Size |
| --- | --- | --- | --- |
| `mrm8488/codebert-base-finetuned-detect-insecure-code` | Confidence signal and attention attribution; never creates rule-less findings unless `CODESHIELD_MODEL_ONLY=true` | `models/detector/` | ~476 MB |
| `Qwen2.5-Coder-1.5B-Instruct` GGUF Q4_K_M | Generates additional repair candidates through an OpenAI-compatible endpoint | `models/repair/*.gguf` | ~1.1 GB |

The detector runs in-process with PyTorch. The repair model runs in a separate
llama.cpp server so the API process stays small and either component can be
restarted independently.

## Download

```bash
make models
# or
.venv/bin/python backend/scripts/download_models.py --all
.venv/bin/python backend/scripts/download_models.py --detector
.venv/bin/python backend/scripts/download_models.py --repair
```

The script uses direct Hugging Face URLs, resumes `.part` files, and skips files
whose size matches. Set `HF_TOKEN` if you hit anonymous rate limits. Models are
gitignored by design; the scripts make the setup reproducible.

## Start the repair endpoint

```bash
make llama            # downloads the prebuilt CPU llama.cpp server
make model-server     # :8080, 4096-token context, 6 threads, no GPU offload
```

Equivalent command:

```bash
.tools/llama-b11753/llama-server \
  -m models/repair/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf \
  -c 4096 -t 6 -ngl 0 --host 127.0.0.1 --port 8080 --jinja --no-webui
```

Check it:

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"qwen","messages":[{"role":"user","content":"Reply READY"}],"max_tokens":8}'
```

Then configure `.env`:

```ini
CODESHIELD_REPAIR_PROVIDER=llm
CODESHIELD_LLM_BASE_URL=http://127.0.0.1:8080/v1
CODESHIELD_LLM_MODEL=qwen2.5-coder-1.5b-instruct
CODESHIELD_LLM_TIMEOUT=180
CODESHIELD_LLM_MAX_TOKENS=1200
```

`CODESHIELD_REPAIR_PROVIDER=auto` resolves to `llm` when either a base URL or a
local `CODESHIELD_REPAIR_MODEL` is configured; otherwise it resolves to `none`.

## Enable the detector

```ini
CODESHIELD_MODEL_MODE=on
CODESHIELD_MODEL_DIR=models/detector
```

`on` requires the model. `auto` uses local weights when present. `off` disables
PyTorch entirely (fast tests and CI). The detector loads once per process; on a
small CPU expect roughly 15 seconds at startup and sub-second inference per code
unit.

Model-only mode is intentionally off by default for precision:

```ini
CODESHIELD_MODEL_ONLY=false
CODESHIELD_MODEL_ONLY_THRESHOLD=0.92
```

With `MODEL_ONLY=true`, high-confidence model findings can appear without a
matching rule. Treat that mode as experimental and review the precision impact on
your own corpus.

## Hardware guidance

| Hardware | Recommended repair model | Notes |
| --- | --- | --- |
| 4–8 GB RAM, CPU only | Qwen2.5-Coder **1.5B Q4_K_M** | Default. Roughly 12 tokens/s on 8 CPU cores. |
| 8–16 GB RAM, CPU only | Qwen2.5-Coder **3B Q4_K_M** | Slower but better patches; tune `-c`, `-t`. |
| 12 GB+ GPU | Qwen2.5-Coder **7B** via llama.cpp with `-ngl` | Set `CODESHIELD_LLM_MODEL` accordingly. |
| CI / no models | none | Templates still produce verified patches. |

Tips for CPU:

- Keep `CODESHIELD_REPAIR_MAX_CANDIDATES=1` or `2` and
  `CODESHIELD_MAX_PATCH_FINDINGS` low for large scans.
- Lower `CODESHIELD_LLM_MAX_TOKENS` to ~800 for small functions.
- Do not run multiple scans concurrently against a single CPU model server.
- Use `CODESHIELD_RETAIN_CODE=false` (default); patch diffs remain available.

## Output contract and robustness

The system prompt asks for:

```json
{"fixes":[{"source":"<complete corrected function>","summary":"...","rationale":"...","semantic_risk":false}]}
```

Small local models often wrap JSON in fences, return a bare array, use
triple-quoted strings, or emit raw newlines inside strings. CodeShield normalizes
all four cases before validation. Candidates are still rejected if they do not
parse, are unchanged, or fail verification.

## Verification

Each candidate is re-parsed, re-scanned for the original CWE, checked for new
high/critical findings and signature preservation, then optionally tested. The
`verification` field is `verified`, `partially_verified`, or `unverified`.

```bash
CODESHIELD_REPAIR_MAX_CANDIDATES=2 \
CODESHIELD_MAX_PATCH_FINDINGS=1 \
.venv/bin/python backend/scripts/run_scan.py samples/vulnerable/app.py \
  --model-mode on --format json --out /tmp/scan.json
```

Inspect `findings[].patch_candidates[]` for `generator`, `verification`,
`checks`, and `unified_diff`.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `No local detector found` | Run `make models`, or set `CODESHIELD_ALLOW_MODEL_DOWNLOAD=1`. |
| Detector unavailable in `/meta` | Confirm `models/detector/config.json` and `pytorch_model.bin` exist. |
| Repair provider `none` | Set `CODESHIELD_LLM_BASE_URL` and restart the API. |
| No LLM candidates | Check `curl` against `:8080`; raise `LLM_TIMEOUT`; lower `LLM_MAX_TOKENS`. |
| Repairs take minutes | CPU model too large or candidate count too high; see hardware guidance. |
| PyTorch install fails on Python 3.14 | Recreate the venv with Python 3.12. |
