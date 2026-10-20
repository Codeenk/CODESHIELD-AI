# Demo runbook

This produces a fully local demo with both models and the repair endpoint.

## 1. Install

```bash
cp .env.example .env
make install
make install-ml
make models
make llama
```

## 2. Configure local models

Add or update `.env`:

```ini
CODESHIELD_MODEL_MODE=on
CODESHIELD_REPAIR_PROVIDER=llm
CODESHIELD_LLM_BASE_URL=http://127.0.0.1:8080/v1
CODESHIELD_LLM_MODEL=qwen2.5-coder-1.5b-instruct
CODESHIELD_LLM_TIMEOUT=180
CODESHIELD_LLM_MAX_TOKENS=1200
CODESHIELD_MAX_PATCH_FINDINGS=5
CODESHIELD_REPAIR_MAX_CANDIDATES=2
CODESHIELD_RUN_TESTS=false
```

The candidate cap keeps CPU-only repair runs responsive.

## 3. Start

Terminal 1:

```bash
make model-server
```

Terminal 2:

```bash
make seed
make serve
```

Open <http://127.0.0.1:8000> and sign in as `demo@codeshield.local` / `demo1234`.

## 4. Walkthrough

1. **Overview** — 13 open findings in the vulnerable demo project, severity mix,
   top CWEs, recent scan history.
2. **New scan** — choose *Snippet*, enter:

   ```python
   import subprocess
   def ping(host):
       subprocess.call("ping -c 1 " + host, shell=True)
   ```

   Enable patches and keep the detector on.
3. **Scan detail** — the CWE-78 finding shows evidence, a knowledge-grounded
   explanation, model attribution, and template plus LLM patch candidates.
4. **Patch review** — open the unified diff, check the verification list, and note
   that LLM candidates are `partially_verified` unless tests prove behavior.
5. **Reports** — export JSON, SARIF, HTML, and PDF.
6. **History / Compare** — compare the vulnerable and clean demo scans to see new,
   fixed, recurring, and resolved findings.
7. **Knowledge** — open a CWE module for attack context and remediation guidance.
8. **Settings** — confirm detector, repair, sandbox, retention, and limits from
   `/api/v1/meta`.

## Expected results

| Scan | Findings | Files |
| --- | --- | --- |
| `samples/vulnerable` | 13 | 3 |
| `samples/clean` | 0 | 1 |
| CodeShield backend self-scan | 0 | — |

The demo seeder uses deterministic template repairs only, so it stays fast even
when the LLM endpoint is running. Live scans still use the configured LLM.

## Reset

```bash
rm -f backend/data/codeshield.db*
make seed
```

## Troubleshooting

- **Dashboard shows model unavailable** — run `make models`, confirm
  `models/detector/config.json` exists, and restart the API.
- **No LLM candidates** — check `curl http://127.0.0.1:8080/v1/models`; verify
  `CODESHIELD_LLM_BASE_URL` ends in `/v1`.
- **Repairs are slow** — lower `CODESHIELD_MAX_PATCH_FINDINGS`,
  `CODESHIELD_REPAIR_MAX_CANDIDATES`, and `CODESHIELD_LLM_MAX_TOKENS`.
- **Port already in use** — stop the old process or set `CODESHIELD_PORT`.
