# CodeShield AI — Product Requirements Document

**Product:** AI-Powered Source Code Vulnerability Scanner &amp; Explainable Auto-Repair Engine
**Team:** Shlok Chavan, Aditya Gaikwad, Sarvesh Malandkar, Yash Bhagwat
**Institution:** Atharva College of Engineering, Dept. of Information Technology (A.Y. 2026-27)
**Document version:** 2.0 (asset-integrated; supersedes v1.0)
**Status:** Draft for review
**Last updated:** October 10, 2026

---

## 0. Document Control

| Field | Value |
| --- | --- |
| Supersedes | *CodeShield AI – Product Requirements Document*, v1.0 (dump preserved in [`_prd_dump.txt`](../_prd_dump.txt)) |
| Reference product | [usestrix/strix](https://github.com/usestrix/strix) — open-source AI penetration-testing tool (Apache-2.0) |
| Reference detection model | [mrm8488/codebert-base-finetuned-detect-insecure-code](https://huggingface.co/mrm8488/codebert-base-finetuned-detect-insecure-code) |
| Vendored assets | Strix-derived skill files + 29 vulnerability knowledge modules under [`backend/codeshield/knowledge/`](../backend/codeshield/knowledge/) |
| License obligations | [`ATTRIBUTION_STRIX_APACHE2_LICENSE.txt`](../ATTRIBUTION_STRIX_APACHE2_LICENSE.txt) (Apache-2.0, © 2025 OmniSecure Inc.) |

### 0.1 What is new in v2.0 versus v1.0

v1.0 was a strong, self-consistent requirements document written from the project presentation. v2.0 keeps all of it and **anchors it to the assets the team has actually imported into the repository**, so that the PRD describes the real project rather than an abstract one. Concretely, v2.0 adds:

1. **A concrete detection model.** v1.0 said "fine-tuned CodeBERT" abstractly. v2.0 pins the starting checkpoint to `mrm8488/codebert-base-finetuned-detect-insecure-code`, documents its measured accuracy (65.30% on Devign/CodeXGLUE), and states clearly what it *cannot* do (binary output, C/C++-only training data, no CWE label). This reframes detection from "a model" into "a model plus the engineering needed to reach the v1.0 targets" (Section 8).
2. **The Strix knowledge layer as a first-class asset.** The repository already vendors an attacker-grade knowledge base — four skill modules and twenty-nine vulnerability modules — extracted from Strix. v2.0 specifies exactly how CodeShield consumes this layer: to ground explanations, to map findings to CWE/OWASP categories, and to drive the exploit-verification step (Section 9).
3. **Attribution and licensing as a requirement.** Because Strix assets are Apache-2.0, v2.0 makes provenance a tracked, testable deliverable rather than an afterthought (FR-40, Section 9.4).
4. **An explicit repo-to-architecture mapping.** The scaffold under `backend/codeshield/` (ingestion, parsing, detection, explain, repair, reporting, sandbox, store, api) is now the authoritative decomposition (Section 6.2).
5. **A stated boundary between static ML and dynamic validation.** CodeShield is a *static, code-visible* scanner; Strix is a *dynamic, exploit-validated* scanner. v2.0 defines how the two cooperate without pretending CodeShield itself executes the target app outside its sandbox (Section 6.3).

Everything in v1.0 that remains valid — problem statement, personas, phasing, metrics, risks, milestones — is carried forward, with asset-specific edits noted inline.

---

## 1. Overview

CodeShield AI is a web platform and CI/CD service that scans source code for security vulnerabilities, shows exactly which lines and syntax nodes caused each finding, and proposes a validated code fix a developer can accept with one click.

It combines three capabilities that existing tools offer only separately:

- **Detection** — a fine-tuned CodeBERT classifier, grounded by Tree-sitter ASTs and cross-checked by a rule-based baseline. The starting checkpoint is the public insecure-code detector `mrm8488/codebert-base-finetuned-detect-insecure-code`.
- **Explanation** — line-level and AST-node-level attribution with a confidence score and a plain-English rationale mapped to a CWE. Explanations are grounded in the vendored Strix vulnerability knowledge base (Section 9), not invented by the LLM.
- **Repair** — a fine-tuned Qwen2.5-Coder model generates a patch, which is verified (re-parsed, re-scanned, and where possible executed under test) before being shown to the user.

### 1.1 Reference lineage

CodeShield AI is not a fork of Strix and does not replace it. Strix is an *active, exploit-validated* pentest agent that runs your application; CodeShield is a *fast, static, in-editor* reviewer that fits into everyday developer flow and CI. The two occupy complementary points on the speed/assurance trade-off, and v2.0 deliberately borrows Strix's **knowledge** (its vulnerability taxonomy, OWASP mapping, and CI/SARIF conventions) while keeping CodeShield's **engine** (CodeBERT + AST + Qwen repair) as its own.

Three sources define the project's DNA:

| Source | Role in CodeShield | License / terms |
| --- | --- | --- |
| [usestrix/strix](https://github.com/usestrix/strix) | Knowledge base, CWE/OWASP mapping methodology, CI + SARIF conventions, honest-coverage posture | Apache-2.0 |
| [mrm8488/codebert-base-finetuned-detect-insecure-code](https://huggingface.co/mrm8488/codebert-base-finetuned-detect-insecure-code) | Detection model starting point | Model card: `en`, trained on CodeXGLUE; base model `microsoft/codebert-base` (MIT) |
| CodeShield team work | Ingestion, parsing, explanation, repair, reporting, dashboard | Project code |

### 1.2 The three-stage flow (unchanged from v1.0, now asset-backed)

```
Ingest → Parse (Tree-sitter AST) → Detect (CodeBERT + rules) → Explain (attribution + Strix KB)
      → Repair (Qwen2.5-Coder) → Verify (re-parse / re-scan / tests in sandbox) → Present
```

---

## 2. Problem Statement

Development teams ship fast through CI/CD and rely heavily on open-source code, which widens the attack surface. Current tooling fails them in three ways:

- **Noisy.** Rule-based SAST tools (SonarQube, Bandit, ESLint security plugins) flag harmless patterns, causing alert fatigue and ignored findings.
- **Opaque.** ML detectors return a score with no explanation of why a block is vulnerable or where the root cause is. This is exactly the limitation of the reference model used as our starting point: it emits a 0/1 verdict and nothing else.
- **Unactionable.** Tools detect but do not fix. General chatbots can suggest fixes but lack repo context and give no reproducible, verified result.

The result is that developers spend a large share of debugging time manually triaging security alerts (the original deck cites over 40%) and known flaw classes keep reaching production. Strix validates this shape of the problem from the dynamic side — it exists precisely because "the false positives of static analysis tools" drive security teams away from legacy scanners — which is why its knowledge base is a sound foundation for a static tool's explanations.

---

## 3. Goals and Non-Goals

### 3.1 Goals

- **G1.** Detect vulnerabilities in supported languages with precision high enough that developers trust the output.
- **G2.** Explain every finding at line and AST-node level, with CWE mapping, OWASP Top 10 category, and severity grounded in the Strix knowledge base.
- **G3.** Generate context-aware patches and verify them before presenting.
- **G4.** Fit into existing workflows: web dashboard, GitHub Action / PR comments, REST API, and later an IDE extension.
- **G5.** Reduce the time from detection to merged fix.
- **G6 (new in v2.0).** Make the knowledge base *first-class and citable*: every finding links to the specific vulnerability module that justified it, and every vendored asset is attributed.

### 3.2 Non-Goals (v1 / MVP)

- Dynamic testing (DAST), fuzzing, or runtime exploitation **inside CodeShield itself**. CodeShield does not run the user's app against a live target; that is Strix's job and CodeShield only borrows Strix's knowledge, not its execution model. (A future "hand off to Strix" integration is a stretch goal — Section 6.3.)
- Dependency / SCA scanning (CVE lookup for libraries). Integrate existing tools later rather than rebuild them.
- Auto-merging patches without human approval.
- Languages beyond Python, JavaScript/TypeScript, and Java in the MVP.
- Guaranteeing zero false negatives. CodeShield is a decision-support tool, not a certification.

---

## 4. Target Users and Personas

| Persona | Needs | How CodeShield helps |
| --- | --- | --- |
| Developer (primary) | Fast, low-noise feedback while coding or in PR review | Inline findings, one-click fix, plain-language explanations |
| Security engineer / AppSec reviewer | Triage at scale, evidence for decisions | Severity + CWE + OWASP tagging, confidence scores, scan history, exportable reports |
| Engineering manager / team lead | Visibility into risk and remediation speed | Dashboard trends, MTTR tracking, PDF reports |
| Student / educator | Learn why code is insecure | Explanations and before/after diffs usable as teaching material |

---

## 5. Scope and Phasing

| Phase | Scope |
| --- | --- |
| **MVP (demo / semester deliverable)** | Python + JavaScript + Java; single-file upload and public GitHub repo link; CodeBERT detection with CWE classification; attention heat-map and AST highlighting; Strix-KB-grounded explanations; patch generation with re-scan check; dashboard; PDF report; scan history |
| **v1.1** | GitHub Action and PR comments; SARIF export; user feedback loop; Semgrep ensemble; knowledge-base coverage report |
| **v1.2** | C/C++ support; unit-test-based patch validation; VS Code extension |
| **v2.0** | Repo-level cross-file data-flow context (code property graph); team workspaces and roles; fine-tuning on private feedback data; optional hand-off of sandbox artifacts to Strix for dynamic validation |

---

## 6. System Architecture

### 6.1 End-to-end pipeline

1. **Ingestion service** — file upload and GitHub link; language detection; filtering of vendored/generated/binary files.
2. **Parsing service** — Tree-sitter AST generation, function extraction, line maps, AST-aware chunking to the model's 512-token window.
3. **Detection service** — fine-tuned CodeBERT classifier (Section 8.1) plus a rule-based scanner running in parallel, with a calibration layer.
4. **Explainability service** — attention aggregation → token → line → AST node, cross-checked by a second attribution method, and grounded against the Strix knowledge base.
5. **Repair service** — Qwen2.5-Coder (LoRA-tuned) generation, candidate ranking, then verification (re-parse, re-scan, optional tests in sandbox).
6. **Presentation layer** — web dashboard, report generator, REST API, GitHub integration.

### 6.2 Repository-to-architecture mapping (as-built scaffold)

The repository scaffold already encodes this decomposition. v2.0 treats these as the canonical module boundaries:

| Path | Responsibility |
| --- | --- |
| [`backend/codeshield/ingestion/`](../backend/codeshield/ingestion/) | Upload, clone, language detection, file filtering |
| [`backend/codeshield/parsing/`](../backend/codeshield/parsing/) | Tree-sitter AST, function extraction, line maps, chunking |
| [`backend/codeshield/detection/`](../backend/codeshield/detection/) | CodeBERT inference, rule ensemble, calibration |
| [`backend/codeshield/explain/`](../backend/codeshield/explain/) | Attribution, AST-node mapping, KB grounding, NL rationale |
| [`backend/codeshield/repair/`](../backend/codeshield/repair/) | Patch generation, candidate ranking |
| [`backend/codeshield/sandbox/`](../backend/codeshield/sandbox/) | Isolated verification environment |
| [`backend/codeshield/reporting/`](../backend/codeshield/reporting/) | PDF / JSON / SARIF generation |
| [`backend/codeshield/store/`](../backend/codeshield/store/) | Scan history and metadata persistence |
| [`backend/codeshield/api/`](../backend/codeshield/api/) | REST API surface |
| [`backend/codeshield/knowledge/`](../backend/codeshield/knowledge/) | **Vendored Strix knowledge base (Section 9)** |
| [`models/`](../models/) | Model weights/registry placeholders |
| [`samples/vulnerable/`](../samples/vulnerable/), [`samples/clean/`](../samples/clean/) | Demo corpus for the test bench |
| [`frontend/src/`](../frontend/src/) | Dashboard (Monaco-based diff view) |
| [`docker/`](../docker/) | Sandbox and service images |
| [`.github/workflows/`](../.github/workflows/), [`.github/actions/codeshield-scan/`](../.github/actions/codeshield-scan/) | CI integration |

### 6.3 The Strix asset layer — how CodeShield uses it

This is the central v2.0 architectural decision. CodeShield consumes Strix assets along **three** seams, and explicitly not a fourth:

- **Explanation grounding (in scope).** When the model flags a function, the explain service retrieves the matching vulnerability module and uses its *description, detection methodology, and remediation guidance* to produce an accurate, citable explanation. This directly addresses the "opaque" and "unactionable" failure modes.
- **Taxonomy mapping (in scope).** Each module carries a slug and content that map naturally onto CWE ids and OWASP Top 10 categories, giving CodeShield a consistent, maintainable severity and classification scheme (Section 9.3).
- **CI conventions (in scope).** The CI skill defines the GitHub Actions shape, exit-code semantics, and SARIF 2.1.0 output that CodeShield mirrors so its PR gate feels familiar to teams already using Strix.
- **Dynamic exploitation (out of scope for the engine, exposed as a hand-off).** CodeShield will *not* ship Strix's exploit machinery. Everything in the Strix knowledge files about running live targets, credentials, and PoCs is reference material; the MVP may offer an opt-in "export this finding as a Strix instruction" hand-off in v2.0, but CodeShield's own sandbox only *tests patches*, never attacks targets.

### 6.4 Suggested stack

React + Monaco Editor (frontend); FastAPI (backend); Celery/Redis or similar job queue; PostgreSQL (metadata and history); object storage for artifacts; PyTorch + Hugging Face Transformers + PEFT for models; Tree-sitter; Docker for sandboxing; GitHub Actions for CI.

---

## 7. Functional Requirements

Priority: **P0** = required for MVP, **P1** = next release, **P2** = future.

### 7.1 Code Ingestion

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-1 | Accept uploads of supported source files (`.py`, `.js`, `.ts`, `.java`) and zipped projects, with size limits (e.g. 5 MB per file, 50 MB per archive). | P0 |
| FR-2 | Accept a GitHub repository URL and clone it read-only; support branch and commit selection. | P0 |
| FR-3 | Detect language automatically; reject unsupported files with a clear message. | P0 |
| FR-4 | Skip vendored, generated, and binary files (`node_modules`, build output, minified bundles). | P0 |
| FR-5 | Support OAuth GitHub App for private repos. | P1 |

### 7.2 Parsing and Preprocessing

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-6 | Parse each file with Tree-sitter to produce an AST; fail gracefully on syntax errors. | P0 |
| FR-7 | Split code into function-level units with line/offset maps so predictions trace back to source lines. | P0 |
| FR-8 | Chunk long functions to respect the model's 512-token window using AST-aware sliding windows. | P0 |
| FR-9 | Build cross-file call graph and taint paths. | P2 |

### 7.3 Vulnerability Detection

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-10 | Classify each function as vulnerable or not, and predict a CWE class (e.g. CWE-89 SQL injection, CWE-79 XSS, CWE-120 buffer overflow, CWE-78 command injection). | P0 |
| FR-11 | Output a calibrated confidence score; users can set a threshold (default tuned for precision). | P0 |
| FR-12 | Assign severity (Critical / High / Medium / Low) from CWE class, confidence, and heuristics. | P0 |
| FR-13 | Run a rule-based scanner (Semgrep/Bandit) in parallel and merge results; label each finding model-only, rule-only, or both. | P1 |
| FR-14 | Suppress findings that match a project's saved false-positive fingerprints. | P1 |

### 7.4 Explainability

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-15 | Extract attention weights and aggregate them to line level; render a heat-map in the editor. | P0 |
| FR-16 | Map attributions onto AST nodes and highlight the top-k nodes as the likely root cause. | P0 |
| FR-17 | Compute a second attribution (Integrated Gradients or SHAP) and show where the two methods agree. | P1 |
| FR-18 | Generate a short natural-language explanation: what the flaw is, why this code triggers it, and the CWE reference. | P0 |
| **FR-36 (new)** | **Ground every explanation in a specific vendored knowledge module and include a citation to it (module slug + CWE/OWASP category).** | P0 |
| **FR-37 (new)** | **Link each finding to its OWASP Top 10 category using the vendored OWASP-mapping knowledge, and label the coverage honestly (e.g. "logging failures are not statically testable").** | P1 |

### 7.5 Automated Repair

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-19 | Generate a patch for each finding using fine-tuned Qwen2.5-Coder, given the vulnerable function, the flagged lines, the CWE, and surrounding context. | P0 |
| FR-20 | Produce up to n candidate patches (default 3), rank them, and show the best with a before/after diff. | P0 |
| FR-21 | Verify each patch: it must parse, must not reintroduce the finding on re-scan, and must preserve syntax and signatures. | P0 |
| FR-22 | Run the project's existing unit tests against the patch in a sandbox where tests are available. | P1 |
| FR-23 | Label patches Verified, Partially verified, or Unverified; never present an unverified patch as safe. | P0 |
| FR-24 | One-click creation of a GitHub branch and pull request containing the accepted patch, with the explanation in the PR description. | P1 |
| **FR-38 (new)** | **Use the vendored remediation guidance for the matched vulnerability class to constrain and sanity-check generated patches (prefer framework built-ins over ad-hoc sanitization, per the Strix fix skill).** | P1 |

### 7.6 Dashboard and Reporting

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-25 | Monaco-based side-by-side view: original with highlights, patched code alongside. | P0 |
| FR-26 | Summary view: counts by severity, CWE distribution chart, files affected. | P0 |
| FR-27 | Finding detail panel: location, CWE, confidence, explanation, patch, status. | P0 |
| FR-28 | Finding lifecycle: Open, Fixed, False Positive, Accepted Risk. | P1 |
| FR-29 | Downloadable PDF report; JSON and SARIF export. | PDF P0, SARIF P1 |
| FR-30 | Scan history with comparison between scans (new, fixed, recurring findings). | P0 |
| **FR-39 (new)** | **Knowledge-base coverage report: which vulnerability modules were exercised, which OWASP categories were assessed, and which could not be assessed.** | P1 |

### 7.7 Integrations and API

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-31 | REST API: submit scan, poll status, fetch results, fetch patch. Token-authenticated. | P0 |
| FR-32 | GitHub Action scanning changed files in a PR, commenting inline, and setting a pass/fail check using a configurable severity gate. | P1 |
| FR-33 | VS Code extension showing findings and applying patches in place. | P2 |

### 7.8 Accounts, Administration, and Provenance

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-34 | Email/GitHub sign-in, per-user scan history. | P0 |
| FR-35 | Team workspaces with roles (admin, member, viewer). | P2 |
| **FR-40 (new)** | **Preserve and display third-party attribution: the Apache-2.0 notice for vendored Strix assets must ship with the repository and any distribution, and each KB-derived explanation must remain citable to its module.** | P0 |

---

## 8. Machine Learning Specification

### 8.1 Detection model card — starting checkpoint

| Field | Value |
| --- | --- |
| Model | `mrm8488/codebert-base-finetuned-detect-insecure-code` |
| Architecture | `RobertaForSequenceClassification` (CodeBERT-base) |
| Size | 12 layers, 768 hidden, 12 attention heads, 50265 vocab, ~125M params |
| Max sequence | 514 tokens (positions) |
| Task | Binary code classification: `0` = secure, `1` = insecure |
| Training data | CodeXGLUE Defect Detection suite, which packages the **Devign** dataset |
| Split | 21,854 train / 2,732 dev / 2,732 test |
| Reported test accuracy | **65.30%** (vs. CodeBERT baseline 62.08%, RoBERTa 61.05%, TextCNN 60.69%, BiLSTM 59.37%) |
| License / terms | Base model `microsoft/codebert-base` (MIT); model card published on Hugging Face |

**Why we start here.** It is a public, reproducible checkpoint that gives the team a working insecure-code classifier on day one, so engineering effort goes into the parts the reference work does not provide (CWE labels, explainability, repair).

**Known limitations we must engineer around (this is a v2.0 requirement, not an optional note).**

1. **Binary, not multi-class.** It predicts *insecure vs secure* only. It does **not** output a CWE. FR-10 therefore requires a separate CWE-classification head/target on top of the frozen backbone.
2. **C/C++ training data.** Devign is C/C++. The MVP targets Python/JS/Java, so cross-language generalisation is an explicit open risk requiring multi-language fine-tuning data (CVEfixes, DiverseVul).
3. **Modest accuracy.** 65.30% on its own test set is well below a usable precision target; the hybrid design (rules + calibrated threshold + KB grounding) is what closes the gap, not the raw model.
4. **Dataset risks.** Label noise, duplicate functions across splits, class imbalance, and synthetic-vs-real gaps. Mitigation: deduplicate, split by project and by time, and use class weighting or focal loss.

### 8.2 Baseline comparison and planned fine-tuning

- **Datasets:** Big-Vul, Devign, CVEfixes, DiverseVul, and NIST Juliet / SARD for CWE-labelled examples. Big-Vul is C/C++-only, so supplement with CVEfixes (multi-language) for Python/JS/Java coverage.
- **Training:** fine-tune with a classification head plus a multi-label CWE head; calibrate with temperature scaling.
- **Alternatives to evaluate:** UniXcoder and GraphCodeBERT, since they incorporate structure and may suit the AST-centred design better than vanilla CodeBERT.
- **Long inputs:** AST-aware chunking is mandatory given the 514-token ceiling.

### 8.3 Explainability

- Aggregate multi-head, multi-layer attention (attention rollout) → token → line → AST node.
- Cross-check with gradient-based attribution (Integrated Gradients) or SHAP; report agreement.
- Validate against ground-truth vulnerable lines extracted from fix commits.
- Ground the natural-language rationale in the vendored knowledge module for the matched class (FR-36).

### 8.4 Repair model

- **Base:** Qwen2.5-Coder (size chosen to fit available GPU, e.g. 1.5B–7B) with LoRA/QLoRA fine-tuning on vulnerability-fix pairs.
- **Input:** vulnerable function, flagged lines, CWE label, brief context (imports, called-function signatures), plus remediation guidance from the knowledge base.
- **Output:** patched function plus a one-line change summary.
- **Guardrails:** constrained to modify only the flagged function; reject outputs that fail to parse or change public signatures.

### 8.5 Evaluation protocol

- Hold out a project-disjoint test set; never tune on it.
- Compare against: Bandit/Semgrep (rule-based), a plain CodeBERT baseline, and an LLM zero-shot baseline.
- Report precision, recall, F1, MCC, AUROC, and per-CWE breakdown.
- Include an ablation: with and without AST features, with and without the rule-based ensemble, with and without KB-grounded prompting.

---

## 9. Knowledge Base Specification (vendored Strix assets)

The repository already contains a curated security knowledge base under [`backend/codeshield/knowledge/`](../backend/codeshield/knowledge/). v2.0 treats it as a versioned product asset with defined consumers, not as loose documentation.

### 9.1 Skill modules

| File | Skill name | Role in CodeShield |
| --- | --- | --- |
| [`skill_find_vulnerabilities.md`](../backend/codeshield/knowledge/skill_find_vulnerabilities.md) | `find-security-vulnerabilities-in-code` | Methodology for white-box review, output schema (`vulnerabilities/*.md`, `vulnerabilities.json`, `findings.sarif`), and "read the results / report honestly" posture |
| [`skill_fix_vulnerabilities.md`](../backend/codeshield/knowledge/skill_fix_vulnerabilities.md) | `fix-security-vulnerabilities-with-strix` | Triage → root-cause fix → re-verify loop; remediation patterns (parameterize queries, object-level authz, allowlists, output encoding) used to constrain repairs (FR-38) |
| [`skill_ci_scanning.md`](../backend/codeshield/knowledge/skill_ci_scanning.md) | `ci-security-scanning-with-strix` | GitHub Actions shape, diff scoping, exit-code semantics, SARIF 2.1.0 upload — mirrored by CodeShield's PR gate (FR-32) |
| [`skill_owasp_top10.md`](../backend/codeshield/knowledge/skill_owasp_top10.md) | `owasp-top-10-testing` | OWASP Top 10:2025 category taxonomy and honest per-category coverage table (FR-37, FR-39) |

### 9.2 Vulnerability knowledge modules (29)

Each module is a self-contained reference for one flaw class. CodeShield uses the slug as a stable key that maps to CWE ids and to the OWASP category table.

**Injection & execution:** `sql_injection`, `nosql_injection`, `argument_injection`, `ssti`, `rce`, `xxe`, `insecure_deserialization`, `prototype_pollution`

**Client-side & browser:** `xss`, `csrf`, `browser_security`, `open_redirect`, `header_injection`

**Access control & identity:** `idor`, `broken_function_level_authorization`, `mass_assignment`, `authentication_jwt`, `weak_password_detection`, `subdomain_takeover`

**Server-side & infrastructure:** `ssrf`, `path_traversal_lfi_rfi`, `insecure_file_uploads`, `http_request_smuggling`, `race_conditions`, `information_disclosure`

**Design & semantics:** `business_logic`, `semantic_confusion`, `agentic_system_security`, `llm_prompt_injection`

> Count check: the `vulnerabilities/` directory contains 29 modules. A machine-readable slug index should be generated from the files at build time so the count and mapping never drift (see Appendix A).

### 9.3 CWE / OWASP mapping approach

- Each detected finding receives a **CWE id** (from the detection/CWE head) and an **OWASP Top 10:2025 category** (from the mapping table derived from `skill_owasp_top10.md`).
- The mapping table must be **data, not code**, so it can be extended without touching the engine.
- Coverage must be reported honestly: categories such as "Security Logging & Alerting Failures" are not statically testable and must be labelled as not assessed rather than passed (mirrors the source skill's posture).

### 9.4 Licensing and attribution

- Vendored Strix assets are **Apache-2.0**; the full license text is preserved in [`ATTRIBUTION_STRIX_APACHE2_LICENSE.txt`](../ATTRIBUTION_STRIX_APACHE2_LICENSE.txt).
- Any modified file must carry a prominent change notice (Apache-2.0 §4b); unmodified assets must retain their notices (§4c).
- The attribution file must not be removed or relocated into build output that excludes it.
- If CodeShield is published, a `NOTICE`/`THIRD_PARTY` section must list Strix (© 2025 OmniSecure Inc.) and the CodeBERT/`microsoft/codebert-base` lineage.

---

## 10. UX Requirements

- **Primary flow:** upload or link → scan progress → summary → finding detail with highlighted code, explanation, and diff → accept/reject.
- **Progressive disclosure:** show severity and a one-line explanation first; reveal attention maps and technical detail on demand.
- **Trust cues:** always show confidence, verification status of each patch, which engine (model, rules, or both) reported the finding, and the KB module that grounds the explanation.
- **Low-friction feedback:** one-click "false positive" and "helpful / not helpful" controls feed the improvement loop.
- **Report:** executive summary, per-finding pages with code snippets and recommended fixes, an appendix with scan configuration and model version, and a knowledge-base coverage section.

---

## 11. Non-Functional Requirements

- **Security of the tool itself.** All cloned or uploaded code is processed in isolated, ephemeral, network-restricted containers. Patch-validation test execution happens only inside the sandbox. Never run uploaded code outside it.
- **Privacy.** Code is not retained after a scan by default (only findings metadata and hashes). Users can opt in to storing code for history. Code is never used for training without explicit consent.
- **Data protection.** TLS in transit, encryption at rest, secret scanning so leaked credentials are masked in the UI and reports.
- **Reliability.** Async job queue with retries; partial results shown if some files fail.
- **Scalability.** Stateless API workers and a separate GPU inference service that scales independently; batching of inference requests.
- **Accessibility and usability.** Keyboard-navigable UI; colour-blind-safe severity palette (never rely on red/green alone).
- **Reproducibility.** Model versions, dataset versions, KB version, and scan configuration are recorded with every result.
- **Compliance alignment.** Findings tagged with CWE and mapped to OWASP Top 10 categories.
- **Provenance.** Third-party attribution is preserved (FR-40).

---

## 12. Success Metrics and Targets

The presentation quotes 92%+ accuracy and a 70%+ MTTR reduction. Those are hypotheses drawn from cited literature, not results, and the reference model's actual published accuracy is only 65.30%. Targets below are to be measured on a held-out set and a small user study.

### 12.1 Model quality

| Metric | Target (MVP) | Notes |
| --- | --- | --- |
| Precision (vulnerable class) | ≥ 80% | Prioritised over recall to reduce alert fatigue |
| Recall (vulnerable class) | ≥ 70% | Report honestly |
| F1 / MCC | Report both | MCC more reliable than accuracy on imbalanced data |
| CWE classification macro-F1 | ≥ 0.70 on top 10 CWEs | Requires the added CWE head, absent from the base checkpoint |
| FP rate vs. Bandit/Semgrep baseline | ≥ 30% lower on the same test set | Direct comparison on identical data |
| Cross-project generalisation | Report the drop vs. random split | Guards against leakage-inflated results |

### 12.2 Explainability quality

| Metric | Target |
| --- | --- |
| Top-5 line localisation hit rate (vs. ground-truth vulnerable lines) | ≥ 60% |
| Developer-rated usefulness (1–5 Likert, small study) | ≥ 4.0 average |
| Explanation grounded to a KB module | 100% of findings (FR-36) |

### 12.3 Repair quality

| Metric | Target |
| --- | --- |
| Patch parses and passes re-scan | ≥ 70% of patches on test set |
| Patch passes existing tests (where available) | ≥ 60% |
| Human-judged "correct and safe" | ≥ 50% for top-1; report top-3 |

### 12.4 Product and performance

| Metric | Target |
| --- | --- |
| Scan latency | &lt; 30 s for a 500-line file; &lt; 5 min for a 50k-LOC repo (GPU) |
| Time to remediate (manual vs. assisted) | ≥ 40% reduction (stretch toward the 70% claim) |
| Patch acceptance rate | ≥ 40% of shown patches accepted |
| False-positive dismissal rate | ≤ 30% of findings |

---

## 13. Risks and Mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Base checkpoint's 65.30% accuracy does not transfer to real code | Over-stated performance, user distrust | Project-disjoint splits, hybrid rules, calibrated threshold, report realistic recall |
| Binary model has no CWE output | Requirement FR-10 unmet | Add a dedicated CWE head trained on CVEfixes/DiverseVul |
| C/C++-trained model on Python/JS/Java | Poor cross-language detection | Multi-language fine-tuning data; per-language evaluation |
| High false positives persist | Alert fatigue defeats the goal | Precision-first threshold, rule ensemble, per-project FP memory |
| Attention is a weak explanation | Misleading highlights | Second attribution method, localisation metric, label as "likely" |
| LLM patch is wrong or introduces a new bug | Security regression | Verification stage, tests, human approval, clear labels |
| Limited GPU resources / student budget | Slow training and inference | LoRA/QLoRA, quantised models, smaller Qwen variant, batching, caching |
| Uploaded code is malicious or leaks secrets | Platform compromise; privacy breach | Sandboxed workers, no execution outside sandbox, secret masking, retention controls |
| Cross-file vulnerabilities missed | False negatives | Document as a limitation; roadmap code property graph in v2.0 |
| Dataset / licence issues | Legal exposure | Track dataset licences; keep Apache-2.0 attribution for Strix assets; avoid training on code without permission |
| Scope too large for the semester | Incomplete MVP | Strict phasing (Section 5); cut PR automation and IDE plugin first |

---

## 14. Milestones (Suggested, ~16 weeks)

| Weeks | Milestone | Deliverable |
| --- | --- | --- |
| 1–2 | Research and data | Dataset selection, cleaning, dedup, project-disjoint splits |
| 3–5 | Detection model | Fine-tuned CodeBERT (from the starting checkpoint) + CWE head, baseline comparison report |
| 6–7 | Parsing and explainability | Tree-sitter pipeline, attention-to-line/AST mapping, KB grounding |
| 8–10 | Repair model | LoRA-tuned Qwen2.5-Coder, verification stage |
| 11–13 | Backend and dashboard | FastAPI services, Monaco UI, PDF report, scan history |
| 14 | Integration and CI | REST API, GitHub Action (stretch), SARIF |
| 15 | Evaluation and user study | Metrics against Section 12, small developer study |
| 16 | Final report and demo | Documentation, presentation, demo video |

---

## 15. Assumptions and Dependencies

- Access to a GPU (local, college lab, or cloud credits) for fine-tuning and inference.
- Public datasets and base models remain available under compatible licences.
- GitHub API access for repository cloning and (optionally) PR creation.
- A group of 5–10 student developers is available for a short usability study.
- The vendored Strix knowledge base remains available under Apache-2.0 and its attribution is preserved.

---

## 16. Open Questions

1. Which languages are essential for the demo: Python, JavaScript, and Java, or C/C++ because of dataset alignment with the base checkpoint?
2. Will the model run locally, on a college server, or in the cloud? This decides model size and latency targets.
3. Is the project judged mainly on research novelty (explainability, evaluation) or on the working product?
4. Should PR-creation be in the MVP or kept as a stretch goal?
5. Is a cloud-hosted public demo needed, or is a local/offline demo acceptable?
6. **Should the MVP expose an opt-in "hand off this finding to Strix for dynamic validation" flow, or is that strictly v2.0?**

---

## 17. References and Asset Provenance

**Reference product and knowledge base**

- usestrix/strix — open-source AI penetration-testing tool. <https://github.com/usestrix/strix> · docs: <https://docs.strix.ai>
- Vendored: [`ATTRIBUTION_STRIX_APACHE2_LICENSE.txt`](../ATTRIBUTION_STRIX_APACHE2_LICENSE.txt) (Apache-2.0, © 2025 OmniSecure Inc.)

**Reference detection model**

- `mrm8488/codebert-base-finetuned-detect-insecure-code`. <https://huggingface.co/mrm8488/codebert-base-finetuned-detect-insecure-code>
- Base model: `microsoft/codebert-base` (MIT).

**Academic**

- Feng, Z., et al. "CodeBERT: A Pre-Trained Model for Programming and Natural Languages." Findings of EMNLP, 2020.
- Zhou, Y., et al. "Devign: Effective Vulnerability Identification by Learning Comprehensive Program Semantics via Graph Neural Networks." NeurIPS, 2019.
- Xia, Y., Shao, H., Deng, X. "VulCoBERT: A CodeBERT-Based System for Source Code Vulnerability Detection." GAIIS / ACM, 2024.
- Hu, Y., et al. "SoK: Automated Vulnerability Repair: Methods, Tools, and Assessments." 34th USENIX Security Symposium, 2025.
- Fan, J., et al. "A C/C++ Code Vulnerability Dataset with Code Changes and CVE Summaries" (Big-Vul), MSR 2020.
- Bhandari, G., et al. "CVEfixes: Automated Collection of Vulnerabilities and Their Fixes from Open-Source Software," PROMISE 2021.
- MITRE CWE Top 25 Most Dangerous Software Weaknesses; OWASP Top 10:2025; OWASP API Security Top 10 (2023).

> **Editorial note carried from v1.0:** the literature table in the original deck lists the same title for two rows. Correct the arXiv/SLR and USENIX titles before final submission.

---

## Appendix A — Asset Inventory

Machine-checkable inventory of the assets integrated in v2.0.

### A.1 Knowledge base

- `backend/codeshield/knowledge/skill_ci_scanning.md`
- `backend/codeshield/knowledge/skill_find_vulnerabilities.md`
- `backend/codeshield/knowledge/skill_fix_vulnerabilities.md`
- `backend/codeshield/knowledge/skill_owasp_top10.md`
- `backend/codeshield/knowledge/vulnerabilities/` — **29 modules:**
  `agentic_system_security`, `argument_injection`, `authentication_jwt`, `broken_function_level_authorization`, `browser_security`, `business_logic`, `csrf`, `header_injection`, `http_request_smuggling`, `idor`, `information_disclosure`, `insecure_deserialization`, `insecure_file_uploads`, `llm_prompt_injection`, `mass_assignment`, `nosql_injection`, `open_redirect`, `path_traversal_lfi_rfi`, `prototype_pollution`, `race_conditions`, `rce`, `semantic_confusion`, `sql_injection`, `ssrf`, `ssti`, `subdomain_takeover`, `weak_password_detection`, `xss`, `xxe`

### A.2 Model registry

| Model | Purpose | Status |
| --- | --- | --- |
| `mrm8488/codebert-base-finetuned-detect-insecure-code` | Detection baseline (binary insecure/secure) | Selected as starting checkpoint |
| `microsoft/codebert-base` | Backbone | Upstream dependency |
| Qwen2.5-Coder (+ LoRA) | Patch generation | To be trained (Section 8.4) |
| CodeShield CWE head | Multi-class CWE classification | To be trained (FR-10) |

### A.3 Repository scaffold

```
backend/codeshield/{ingestion,parsing,detection,explain,repair,sandbox,reporting,store,api}/
backend/codeshield/knowledge/{skill_*.md, vulnerabilities/*.md}
backend/scripts/  backend/tests/
frontend/src/{components,lib,styles}/
models/
samples/{vulnerable,clean}/
docker/
.github/{workflows/, actions/codeshield-scan/}
docs/
```

---

## Appendix B — Traceability: reference PRD → v2.0 additions

| v1.0 element | v2.0 treatment |
| --- | --- |
| "fine-tuned CodeBERT" | Pinned to a named model with a model card (Section 8.1) |
| "attention heat-map" | Kept, plus KB-grounding and a localisation metric |
| "rule-based baseline (Semgrep/Bandit)" | Kept as FR-13 |
| "Qwen2.5-Coder repair" | Kept, plus KB-constrained prompting (FR-38) |
| Metrics section | Restated as targets, anchored to the reference model's real 65.30% |
| New | FR-36..FR-40, Section 9 (KB spec), Appendix A (asset inventory) |
