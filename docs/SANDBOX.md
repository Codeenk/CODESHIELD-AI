# Sandbox and patch verification

Patch verification is **static by default**. Dynamic tests run only when both a
project contains tests and test execution is explicitly enabled.

## Modes

| `CODESHIELD_SANDBOX` | Behavior |
| --- | --- |
| `auto` (default) | Use Docker when `CODESHIELD_SANDBOX_IMAGE` exists locally; otherwise fall back to a constrained subprocess. |
| `docker` | Use Docker when the image exists; otherwise fall back to subprocess. |
| `subprocess` | Always use the constrained subprocess runner. |
| `off` / `disabled` | Never execute project tests; verification stays static. |

```ini
CODESHIELD_RUN_TESTS=false
CODESHIELD_SANDBOX=auto
CODESHIELD_TEST_TIMEOUT=120
CODESHIELD_TEST_COMMAND=python -m pytest -q
CODESHIELD_SANDBOX_MEMORY=1g
CODESHIELD_SANDBOX_CPUS=1
```

## What tests are executed

The runner detects `tests/`, `test/`, `test_*.py`, or `*_test.py` in repository
and archive scans. Uploaded files and snippets have no workspace, so they never
run tests.

For each candidate:

1. Run the unmodified project once as a baseline.
2. Copy the project to a temporary directory.
3. Replace the target file with the candidate source.
4. Run the configured command.
5. Verify the file path stays inside the temporary workspace.

If the baseline fails, the test result is skipped and the candidate cannot be
called `verified` on test evidence.

## Docker sandbox

Build the image once:

```bash
docker build -f docker/Dockerfile -t codeshield-sandbox:latest .
```

The runner checks `docker image inspect CODESHIELD_SANDBOX_IMAGE`. If the image is
present, tests run with:

- `--network none`
- memory and CPU limits
- `--pids-limit 256`
- `--cap-drop ALL`
- `--security-opt no-new-privileges`
- a read-write bind mount of the temporary project only

The repository does not build the image automatically. If the daemon is down or
the image is missing, `auto` falls back to the subprocess runner. Inspect
`/api/v1/meta` for the effective mode.

## Subprocess fallback

The fallback is useful on workstations and CI without Docker, but it is **not a
security boundary**. It uses `start_new_session`, a clean environment, a timeout,
and POSIX resource limits (`RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_NPROC`,
`RLIMIT_FSIZE`). It does not isolate the filesystem or network.

Do not enable tests for untrusted repositories unless Docker is available and the
image is present.

## Verification status

| Status | Meaning |
| --- | --- |
| `verified` | Parses, original weakness is gone, no new high/critical finding, signature preserved, and available tests pass. |
| `partially_verified` | Static checks passed, but the change is semantically risky or dynamic tests were unavailable/skipped. |
| `unverified` | One or more checks failed or could not run. |

Every candidate keeps its `checks` list so the UI can show exactly which evidence
passed.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Tests found but not executed | Set `CODESHIELD_RUN_TESTS=true` and restart. |
| Docker daemon unavailable | Start Docker, or set `CODESHIELD_SANDBOX=subprocess` explicitly. |
| Baseline tests fail | Fix the project tests first; patch testing is inconclusive. |
| Tests time out | Raise `CODESHIELD_TEST_TIMEOUT` or reduce the test command scope. |
| Tests pass locally but not in Docker | The image must contain the language runtime and test dependencies. |
