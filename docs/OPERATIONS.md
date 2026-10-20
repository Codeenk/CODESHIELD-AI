# Operations

## Runtime model

CodeShield is a single FastAPI process with:

- SQLite in WAL mode at `CODESHIELD_DB` (default `backend/data/codeshield.db`).
- An in-process worker pool (`CODESHIELD_JOB_WORKERS`, default 3).
- In-process scan jobs, so **run exactly one server process** with a shared DB.
- On startup, stale `running` scans are marked interrupted.

Horizontal scaling requires a shared database and an external queue; that is not
implemented. Scale vertically or run separate instances with separate databases.

## Deploy

```bash
make build
cd backend && CODESHIELD_HOST=0.0.0.0 CODESHIELD_PORT=8000 \
  ../.venv/bin/python -m codeshield
```

Or with Docker:

```bash
docker build -f docker/Dockerfile -t codeshield:latest .
docker run --rm -p 8000:8000 \
  -e CODESHIELD_AUTH=on \
  -e CODESHIELD_SECRET_KEY='replace-with-32-plus-random-bytes' \
  -v codeshield-data:/data \
  codeshield:latest
```

Set `CODESHIELD_DATA_DIR=/data` when mounting a volume. The image serves the
built frontend and API from the same origin.

## Authentication

| Mode | Configuration |
| --- | --- |
| Local accounts | `CODESHIELD_AUTH=on` (default) |
| Single user | `CODESHIELD_AUTH=off` |
| GitHub OAuth | Set `CODESHIELD_GITHUB_CLIENT_ID`, `CODESHIELD_GITHUB_CLIENT_SECRET`, and the callback URL |
| CI bearer token | Set `CODESHIELD_API_TOKEN` and send `Authorization: Bearer ...` |

Use a stable `CODESHIELD_SECRET_KEY` for OAuth state signing. Set
`CODESHIELD_COOKIE_SECURE=true` behind HTTPS. Passwords use `scrypt`; session
tokens are opaque and hashed at rest. Login attempts are rate-limited in-process.

## Reverse proxy

Terminate TLS at the proxy and forward to `127.0.0.1:8000`. Preserve the original
`Host` and client address if you rely on rate limiting. Set
`CODESHIELD_FRONTEND_URL` to the public origin and use HTTPS for the OAuth
callback. The app sets CSP, `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, and `Referrer-Policy: no-referrer`.

## Backups

SQLite is the only stateful store. Back up the database and `CODESHIELD_DATA_DIR`
together while the server is stopped, or use SQLite's online backup API.

```bash
sqlite3 backend/data/codeshield.db ".backup '/backups/codeshield-$(date +%F).db'"
```

Reports are generated on demand; only evidence snippets, patch diffs, and metadata
are stored.

## Privacy controls

| Setting | Default | Effect |
| --- | --- | --- |
| `CODESHIELD_RETAIN_CODE` | `false` | Discard full function bodies after scan; keep evidence and diffs. |
| `CODESHIELD_MASK_SECRETS` | `true` | Mask credentials before persistence and export. |
| `CODESHIELD_MAX_FILES` | 4000 | Per-scan file cap. |
| `CODESHIELD_MAX_FILE_BYTES` | 5 MB | Per-file cap. |
| `CODESHIELD_MAX_TOTAL_BYTES` | 80 MB | Upload total cap. |
| `CODESHIELD_MAX_ARCHIVE_BYTES` | 50 MB | Archive cap before extraction. |
| `CODESHIELD_MAX_ACTIVE_SCANS` | 3 | Per-user concurrency cap. |

Repository ingestion is HTTPS-only, host-allowlisted, depth-1, and read-only.

## Reports and CI

```bash
python backend/scripts/run_scan.py backend/codeshield --fail-on high
python backend/scripts/run_scan.py samples/vulnerable --format sarif --out codeshield.sarif
```

Exit codes: `0` clean at the gate, `2` findings at/above the gate, `1` runtime or
ingestion error. The GitHub action under `.github/actions/codeshield-scan` wraps
the CLI and uploads SARIF.

## Health and observability

- `GET /api/v1/health` — process and database check.
- `GET /api/v1/meta` — model, repair, sandbox, privacy, and limits.
- `GET /api/v1/stats` — dashboard aggregates.
- Logs go to stderr; set `CODESHIELD_LOG_LEVEL`.

Monitor scan failures, job queue depth, the detector `used` flag, and the repair
endpoint separately. A failed model or endpoint must never stop rules-only
scanning.

## Upgrades

1. Back up the database.
2. Pull the new code and rebuild the frontend.
3. Run `make test` and `make scan`.
4. Restart the process once. Schema initialization is additive; stale running
   scans are reconciled at startup.

## Known limitations

- Business logic, authorization, and race conditions need manual review.
- Rules are review candidates, not proof of exploitability.
- Dependencies, infrastructure configuration, and generated code are out of scope.
- The in-process queue and SQLite are intended for a single node.
- The subprocess test runner is not a security boundary.
