# PRD → implementation traceability

This table maps every functional requirement in [PRD.md](../PRD.md) to where it is implemented
and how it is verified. Status legend:

- **Done** — implemented and covered by the test-suite.
- **Partial** — implemented with a documented limitation.
- **Deferred** — explicitly out of the current build (see PRD §6 phasing).

| Req | Status | Where | Verified by |
| --- | --- | --- | --- |
| FR-1 file/zip upload, size limits | Done | [`core/ingestion.py`](../codeshield/core/ingestion.py) | `tests/test_ingestion.py` |
| FR-2 GitHub URL, branch/commit | Done | `ingest_github()` | manual / `tests/test_api.py::test_github_rejects_non_github_url` |
| FR-3 auto language detection, reject others | Done | `detect_language()` | `tests/test_ingestion.py` |
| FR-4 skip vendored/generated/binary | Done | `should_skip_path()`, `_decode()` | `tests/test_ingestion.py` |
| FR-5 private repos (OAuth App) | Deferred (P1) | — | — |
| FR-6 Tree-sitter AST, graceful fallback | Partial | [`core/parsing.py`](../codeshield/core/parsing.py) uses Python `ast` + a brace heuristic; Tree-sitter is detected and used when installed | `tests/test_scan.py` |
| FR-7 function units + line maps | Done | `analyze_file()`, `snippet_for()` | `tests/test_scan.py`, `tests/test_repair.py` |
| FR-8 512-token chunking | Done | `chunk_unit()` | unit-level |
| FR-9 cross-file call graph / taint | Deferred (P2) | — | — |
| FR-10 vulnerable/CWE classification | Done (model accuracy weak — see below) | [`core/detection.py`](../codeshield/core/detection.py), [`core/rules.py`](../codeshield/core/rules.py) | `tests/test_rules.py`, `tests/test_scan.py`, `tests/test_detection_model.py` |
| FR-11 confidence + threshold | Partial | configurable `CODESHIELD_MODEL_THRESHOLD`; probability calibration (temperature scaling) not implemented; measurement shows thresholds cannot separate the classes on the smoke set | `tests/test_severity.py`, `scripts/eval_model.py` |
| FR-12 severity from CWE + confidence | Done | [`core/severity.py`](../codeshield/core/severity.py) | `tests/test_severity.py` |
| FR-13 rule-based ensemble + agreement labels | Done (rules) / Partial (Semgrep not bundled) | `DetectionService.detect()` | `tests/test_scan.py` |
| FR-14 false-positive suppression | Done | `ScanOptions.suppress_fingerprints` | `tests/test_scan.py::test_suppressed_fingerprint_is_removed` |
| FR-15 attention → line heat-map | Done | `_attention_to_lines()` (eager attention forced), `salience_lines()` | `tests/test_scan.py`, `tests/test_detection_model.py::test_attention_is_available_for_the_heatmap` |
| FR-16 AST-node attribution | Done | `syntax_nodes_for()` | `tests/test_scan.py` |
| FR-17 second attribution + agreement | Partial | `second_opinion()` uses a transparent salience method (not Integrated Gradients/SHAP) | `tests/test_scan.py` |
| FR-18 plain-English explanation | Done | `build_rationale()` | `tests/test_scan.py` |
| FR-19 patch generation (model) | Partial | template fixers + optional LLM endpoint; no fine-tuned Qwen weights shipped | `tests/test_repair.py` |
| FR-20 up to n candidates, ranked | Done | `generate_candidates()` | `tests/test_repair.py` |
| FR-21 verify parse + re-scan + signature | Done | [`core/verify.py`](../codeshield/core/verify.py) | `tests/test_repair.py` |
| FR-22 run project tests in sandbox | Partial | sandbox image provided ([`docker/sandbox.Dockerfile`](../docker/sandbox.Dockerfile)); runner not wired | — |
| FR-23 verified/partial/unverified labels | Done | `PatchStatus` | `tests/test_repair.py` |
| FR-24 one-click GitHub PR | Deferred (P1) | — | — |
| FR-25 Monaco side-by-side view | Partial | dashboard renders a styled unified diff with before/after patches; Monaco editor not embedded | manual |
| FR-26 summary (severity, CWE, files) | Done | dashboard `renderScan()` + `ScanSummary` | manual / `tests/test_api.py` |
| FR-27 finding detail panel | Done | dashboard `selectFinding()` | manual |
| FR-28 finding lifecycle | Done | `POST /api/scans/{id}/findings/{fid}/status` | `tests/test_api.py::test_lifecycle_update` |
| FR-29 PDF / JSON / SARIF export | Done | [`report/`](../codeshield/report) | `tests/test_report.py` |
| FR-30 scan history + comparison | Partial | `GET /api/scans` lists history; scan-to-scan diff not implemented | `tests/test_api.py` |
| FR-31 token-authenticated REST API | Done | [`api/app.py`](../codeshield/api/app.py) | `tests/test_api.py::test_auth_required_when_token_set` |
| FR-32 GitHub Action + severity gate | Done | [`action.yml`](../action.yml), [`.github/workflows/codeshield-scan.yml`](../.github/workflows/codeshield-scan.yml) | CI |
| FR-33 VS Code extension | Deferred (P2) | — | — |
| FR-34 accounts / per-user history | Deferred | — | — |
| FR-35 team workspaces | Deferred (P2) | — | — |

## Non-functional requirements (PRD §9)

| Requirement | Where |
| --- | --- |
| Sandboxed execution; no code execution outside it | [`docker/sandbox.Dockerfile`](../docker/sandbox.Dockerfile), `verify.py` (tests skipped without a sandbox) |
| No code retention by default | `CODESHIELD_RETAIN_CODE` (default `0`); only metadata + SHA-256 hashes persisted |
| Secret masking in UI/reports | `rules.mask_secrets()`, applied to snippets and to every patch (see the regression test `test_secrets_are_masked_in_results`) |
| Partial results on failure | `Scanner._scan_one()` records a per-file skip reason instead of failing the scan |
| Reproducibility | `ScanResult.model_version`, `config`, and dataset/model IDs recorded per scan |

## Detection model

`mrm8488/codebert-base-finetuned-detect-insecure-code` is integrated in
[`core/detection.py`](../codeshield/core/detection.py) via `AutoTokenizer` +
`AutoModelForSequenceClassification` (512-token window, `LABEL_0`=secure / `LABEL_1`=insecure,
attention rollout to lines). It is loaded lazily and forced to **eager** attention, because
`transformers>=5` defaults to `sdpa`, which silently returns no attention tensors and left the
line-level heat-map empty (FR-15). Regression test:
`tests/test_detection_model.py::test_attention_is_available_for_the_heatmap`.

**Verification status: executed.** The checkpoint was downloaded (~476 MB) and run on CPU
(`torch 2.14.1`, `transformers 5.19.0`) in the environment that produced this document. All six
model tests passed (`tests/test_detection_model.py`, 6 passed).

### Measured results — 20-sample smoke set ([`scripts/eval_model.py`](../scripts/eval_model.py))

| Detector | Precision | Recall | F1 | Accuracy | MCC |
| --- | --- | --- | --- | --- | --- |
| CodeBERT checkpoint alone (threshold 0.55) | 0.50 | 0.90 | 0.643 | 0.50 | **0.00** |
| Rule-based baseline | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |

The checkpoint scored **9 of 10 clean functions as insecure** at ≈0.99, i.e. it is **not
discriminative on its own** (MCC 0.00 — no better than chance on this set) and it missed the
hard-coded credential (0.024). This matches the published warning that benchmark accuracy for
this model family does not transfer to real code.

**Product consequence, implemented:** a model hit with no rule support is capped at **medium**
severity, labelled *unconfirmed*, and can therefore never trip the CI gate (which only counts
high+). See `model_only_severity()` and `tests/test_detection_model.py`. Model + rule agreement
is where the model adds value: it upgraded 10 example findings to `Engine.both` and raised their
confidence.

**Caveat:** this 20-sample set is a smoke check written to exercise the path, **not** the
project-disjoint held-out benchmark PRD §8.1 requires. These numbers must not be quoted as
CodeShield's accuracy; the model card's own 65.3% is on a random (non-disjoint) split.

## Reference-project assets reused (usestrix/strix)

| Strix asset | CodeShield adaptation |
| --- | --- |
| `strix/skills/*` knowledge packs | [`codeshield/skills/`](../codeshield/skills) — CWE packs with YAML front-matter |
| `strix/agents/factory.py` + `prompt.py` | [`codeshield/agents/factory.py`](../codeshield/agents/factory.py) — up-to-5 skill selection into agent prompts |
| `strix/report` + SARIF | [`codeshield/report/sarif.py`](../codeshield/report/sarif.py) — SARIF 2.1.0 |
| `containers/Dockerfile` sandbox | [`docker/sandbox.Dockerfile`](../docker/sandbox.Dockerfile) — no-network, read-only test runner |
| README GitHub Actions usage | [`action.yml`](../action.yml) + [`.github/workflows/codeshield-scan.yml`](../.github/workflows/codeshield-scan.yml) |
| `strix_runs/` output convention | `<repo>/.codeshield/` artefacts (git-ignored) |
