# CodeShield AI — System Architecture & Pseudocode

This document outlines the end-to-end algorithmic flow and core components of **CodeShield AI** in high-level pseudocode.

---

## Architecture Overview

```text
               +-------------------------------------------+
               |        User Interface / REST API          |
               +-------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                            Ingestion Engine                             |
|  - Shallow Git Clone (Normalized Windows/POSIX subprocess)              |
|  - Multipart File Uploads (Preserved folder hierarchy)                 |
|  - Zip Archive Unpacking (Zip-bomb & traversal protected)               |
|  - Snippet Input                                                        |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                             Parsing Engine                              |
|  - Python AST Parser                                                    |
|  - Tree-sitter Grammar Pack (JS, TS, TSX, Java)                         |
|  - Output: List[CodeUnit] (functions, methods, script bodies)           |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                            Detection Engine                             |
|  - 38+ Deterministic Rules (AST pattern matching)                      |
|  - Scoped Taint Engine (Sources -> Sanitizers -> Sinks)                 |
|  - [Optional] CodeBERT Insecure-Code Classifier                         |
|  - [Optional] Attention-Rollout Line Attribution                        |
|  - Deduplication & Deterministic Fingerprinting                         |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                           Explanation Engine                            |
|  - Vendored CWE/OWASP Knowledge Base Grounding                          |
|  - Evidence Attribution & Remediation Guide Generation                  |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                              Repair Engine                              |
|  - Deterministic AST/Regex Templates                                    |
|  - [Optional] Local LLM (Qwen2.5-Coder via llama.cpp)                   |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                           Verification Sandbox                          |
|  - Check 1: Target language syntax parsing                              |
|  - Check 2: Original CWE vulnerability eliminated                       |
|  - Check 3: No new High/Critical vulnerabilities introduced             |
|  - Check 4: Function signature & API contract preserved                 |
|  - Check 5: Project unit test suite execution (if enabled)              |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                       Storage, Reports & Dashboard                      |
|  - SQLite (WAL Mode), SARIF 2.1.0, JSON, Standalone HTML & PDF          |
+-------------------------------------------------------------------------+
```

---

## 1. Top-Level Scan Pipeline

```python
FUNCTION RunScanPipeline(scan_job, source_input, progress_callback, cancel_check):
    """
    Main orchestration function executed in background worker thread pool.
    """
    TRY:
        # Step 1: Ingest source into a temporary sandboxed workspace
        progress_callback(stage="ingesting", percent=5)
        cancel_check()
        workspace = IngestSource(source_input)

        # Step 2: Parse source files into discrete CodeUnits
        progress_callback(stage="parsing", percent=15)
        cancel_check()
        code_units = []
        FOR EACH (file_path, content) IN workspace.files:
            units = ParseFile(file_path, content)
            code_units.extend(units)

        IF code_units IS EMPTY:
            RAISE IngestionError("No supported source files found")

        # Step 3: Run deterministic detection + ML confidence fusion
        progress_callback(stage="detecting", percent=35)
        cancel_check()
        detection_result = DetectWeaknesses(code_units, model_mode=scan_job.model_mode)
        findings = detection_result.findings

        # Apply project-level suppression rules
        suppressed_map = Store.GetSuppressionMap(scan_job.project_id)
        FOR EACH finding IN findings:
            IF finding.fingerprint IN suppressed_map:
                finding.status = suppressed_map[finding.fingerprint]
                finding.suppressed = True

        # Step 4: Ground findings with explanations & remediation
        progress_callback(stage="explaining", percent=50)
        cancel_check()
        active_findings = [f FOR f IN findings IF NOT f.suppressed]
        FOR EACH finding IN active_findings:
            unit = FindCodeUnit(code_units, finding.path, finding.function, finding.start_line)
            finding.explanation = GenerateExplanation(finding, unit, detection_result.model_used)

        # Step 5: Propose and verify patches
        IF scan_job.config.generate_patches AND active_findings IS NOT EMPTY:
            progress_callback(stage="repairing", percent=65)
            cancel_check()
            test_runner = InitializeTestRunner(workspace.root, workspace.files)
            
            FOR EACH finding IN active_findings[0 : MAX_PATCH_BUDGET]:
                cancel_check()
                unit = FindCodeUnit(code_units, finding.path, finding.function, finding.start_line)
                IF unit IS NOT NULL:
                    raw_fixes = GenerateRepairs(finding, unit)
                    verified_patches = VerifyRepairs(finding, unit, raw_fixes, test_runner)
                    finding.patch_candidates = verified_patches

        # Step 6: Finalize & Persist
        progress_callback(stage="finalizing", percent=90)
        summary = BuildScanSummary(scan_job, findings, code_units, detection_result)
        Store.SaveScanResults(scan_job, findings, summary)
        progress_callback(stage="completed", percent=100)

    FINALLY:
        workspace.Cleanup()
```

---

## 2. Ingestion Engine

```python
FUNCTION IngestSource(source_input):
    """
    Safely unpacks or clones input into a managed temporary workspace directory.
    """
    SWITCH source_input.type:

        CASE "repo":
            # Sanitize and normalize URL
            url = NormalizeRepoURL(source_input.url)
            # Auto-extract branch if URL was copied from browser e.g. /tree/<branch>
            branch = source_input.branch OR ExtractBranchFromURL(source_input.url)
            commit = source_input.commit

            temp_dir = CreateTempDirectory("codeshield-repo-")
            target_repo_dir = temp_dir / "repo"

            # Execute shallow single-branch git clone
            env = MergeSystemEnv({
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_ALLOW_PROTOCOL": "https",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null" (or os.devnull),
                "GCM_INTERACTIVE": "never",
                "LC_ALL": "C"
            })
            IF OS IS NOT Windows:
                env["GIT_ASKPASS"] = "/bin/true"

            RunSubprocess(
                ["git", "clone", "--depth", "1", "--single-branch", "--no-tags",
                 "--recurse-submodules=no", "--no-local", "--branch", branch, "--", url, target_repo_dir],
                env=env, timeout=180
            )

            IF commit IS PROVIDED:
                RunSubprocess(["git", "-C", target_repo_dir, "fetch", "--depth", "1", "origin", commit], env=env)
                RunSubprocess(["git", "-C", target_repo_dir, "checkout", "--detach", "FETCH_HEAD"], env=env)

            files = CollectSupportedFiles(target_repo_dir)
            RETURN Workspace(root=target_repo_dir, files=files, source_type="repo")

        CASE "upload":
            temp_dir = CreateTempDirectory("codeshield-upload-")
            files = {}
            FOR EACH (relative_name, payload) IN source_input.files:
                safe_rel_path = SanitizeRelativePath(relative_name)

                # Transparent zip extraction even when uploaded under Files mode
                IF IsZipFile(safe_rel_path, payload):
                    zip_files = UnpackZipToWorkspace(temp_dir, payload)
                    files.UPDATE(zip_files)
                ELSE IF HasSupportedLanguageExtension(safe_rel_path):
                    decoded_text = DecodeText(payload)
                    IF decoded_text IS NOT NULL:
                        WriteFile(temp_dir / safe_rel_path, decoded_text)
                        files[safe_rel_path] = decoded_text

            RETURN Workspace(root=temp_dir, files=files, source_type="upload")

        CASE "zip":
            temp_dir = CreateTempDirectory("codeshield-zip-")
            files = UnpackZipToWorkspace(temp_dir, source_input.zip_bytes)
            RETURN Workspace(root=temp_dir, files=files, source_type="zip")

        CASE "snippet":
            temp_dir = CreateTempDirectory("codeshield-snippet-")
            filename = SanitizeRelativePath(source_input.filename OR "snippet.py")
            WriteFile(temp_dir / filename, source_input.code)
            RETURN Workspace(root=temp_dir, files={filename: source_input.code}, source_type="snippet")
```

---

## 3. Parsing Engine

```python
FUNCTION ParseFile(file_path, content):
    """
    Parses source code into structured CodeUnit objects representing functions,
    methods, and module-level blocks.
    """
    language = DetectLanguage(file_path)
    
    IF language == "python":
        TRY:
            ast_tree = StandardLibraryAST.parse(content)
            units = []
            FOR EACH node IN WalkAST(ast_tree):
                IF node IS FunctionDef OR node IS AsyncFunctionDef:
                    units.APPEND(CodeUnit(
                        path=file_path,
                        language="python",
                        name=node.name,
                        start_line=node.lineno,
                        end_line=node.end_lineno,
                        source=GetSourceLines(content, node.lineno, node.end_lineno),
                        signature=BuildPythonSignature(node),
                        kind="function"
                    ))
            # If no functions found, treat entire file as a module unit
            IF units IS EMPTY:
                units.APPEND(CodeUnit(path=file_path, language="python", name="<module>",
                                      start_line=1, end_line=LineCount(content), source=content, kind="module"))
            RETURN units
        EXCEPT SyntaxError:
            RETURN FallbackTolerantRegexParser(file_path, content, "python")

    ELSE IF language IN ["javascript", "typescript", "tsx", "java"]:
        TRY:
            tree_sitter_parser = GetTreeSitterParser(language)
            tree = tree_sitter_parser.parse(content)
            query = GetLanguageFunctionQuery(language)
            matches = query.matches(tree.root_node)
            
            units = []
            FOR EACH match IN matches:
                func_node = match["function_node"]
                name = ExtractNodeIdentifier(func_node)
                units.APPEND(CodeUnit(
                    path=file_path,
                    language=language,
                    name=name,
                    start_line=func_node.start_point.row + 1,
                    end_line=func_node.end_point.row + 1,
                    source=content[func_node.start_byte : func_node.end_byte],
                    signature=ExtractNodeSignature(func_node),
                    kind="function"
                ))
            IF units IS EMPTY:
                units.APPEND(CodeUnit(path=file_path, language=language, name="<file>",
                                      start_line=1, end_line=LineCount(content), source=content, kind="file"))
            RETURN units
        EXCEPT TreeSitterError:
            RETURN FallbackTolerantRegexParser(file_path, content, language)
```

---

## 4. Detection Engine & Taint Tracking

```python
FUNCTION DetectWeaknesses(code_units, model_mode):
    """
    Evaluates 38 deterministic rules with scoped taint tracking,
    then optionally combines findings with CodeBERT probability.
    """
    all_findings = []
    
    FOR EACH unit IN code_units:
        unit_rule_hits = []

        # 1. Deterministic AST & Taint Evaluation
        FOR EACH rule IN RULE_CATALOG:
            IF rule.language != unit.language AND rule.language != "any":
                CONTINUE

            # Locate dangerous sink nodes (e.g. cursor.execute, eval, subprocess.run)
            sinks = FindMatchingSinks(unit, rule.sink_patterns)
            FOR EACH sink IN sinks:
                # Trace whether unvalidated user input reaches sink
                taint_path = TraceTaint(
                    unit=unit,
                    sink_arg=sink.target_arg,
                    sources=RULE_TAINT_SOURCES,      # request.args, os.environ, sys.argv, etc.
                    sanitizers=rule.safe_sanitizers  # int(), shlex.quote(), parameterized queries
                )
                
                IF taint_path.is_tainted:
                    unit_rule_hits.APPEND(RuleHit(
                        rule=rule,
                        sink=sink,
                        taint_path=taint_path,
                        evidence=BuildEvidenceSnippet(unit, sink, taint_path)
                    ))

        # 2. Optional CodeBERT ML Classification & Confidence Fusion
        model_probability = NULL
        attention_weights = NULL

        IF model_mode != "off" AND ModelIsLoaded():
            # Run CodeBERT classification
            tokens, logits, attentions = CodeBERT.Forward(unit.source)
            raw_prob = Softmax(logits)[INSECURE_CLASS_INDEX]
            model_probability = CalibrateProbability(raw_prob) # Platt scaling

            # Compute attention rollout for line-level explainability
            attention_weights = ComputeAttentionRollout(attentions, tokens)

        # 3. Fuse Deterministic + Learned Signals
        FOR EACH hit IN unit_rule_hits:
            confidence = hit.rule.default_confidence  # "high", "medium", or "low"
            
            IF model_probability IS NOT NULL:
                IF model_probability >= 0.75:
                    confidence = ElevateConfidence(confidence)
                ELSE IF model_probability <= 0.35:
                    confidence = LowerConfidence(confidence)

            finding = CreateFinding(
                unit=unit,
                hit=hit,
                confidence=confidence,
                model_score=model_probability,
                attention=attention_weights,
                fingerprint=ComputeDeterministicFingerprint(unit.path, hit.rule.cwe, hit.sink.line)
            )
            all_findings.APPEND(finding)

    RETURN DetectionResult(findings=DeduplicateFindings(all_findings))
```

---

## 5. Explanation Engine

```python
FUNCTION GenerateExplanation(finding, unit, model_used):
    """
    Grounds finding against the vendored vulnerability knowledge base.
    """
    kb_module = KnowledgeBase.Lookup(finding.cwe)
    
    # 1. Map attack vector
    attack_path = []
    IF finding.evidence.taint_source:
        attack_path.APPEND(f"Input enters from {finding.evidence.taint_source.name}")
    IF finding.evidence.assignments:
        attack_path.APPEND(f"Variable flows through {len(finding.evidence.assignments)} assignments without sanitization")
    attack_path.APPEND(f"Value reaches dangerous execution sink at line {finding.line}")

    # 2. Extract remediation guidance
    remediation_steps = kb_module.GetRemediationSteps(unit.language)
    safe_examples = kb_module.GetCodeExamples(unit.language)

    # 3. Attention rollout mapping
    line_attributions = []
    IF model_used AND finding.attention_weights:
        line_attributions = MapTokensToLines(unit.source, finding.attention_weights)

    RETURN Explanation(
        title=kb_module.title,
        cwe_description=kb_module.description,
        owasp_category=kb_module.owasp,
        attack_path=attack_path,
        remediation=remediation_steps,
        safe_example=safe_examples,
        highlighted_lines=line_attributions
    )
```

---

## 6. Repair Generation & Verification

```python
FUNCTION GenerateRepairs(finding, unit):
    """
    Generates patch candidates using deterministic templates and/or local LLM.
    """
    candidates = []

    # 1. Deterministic AST/Regex Templates
    template_fix = TemplateEngine.GenerateFix(finding, unit)
    IF template_fix IS NOT NULL:
        candidates.APPEND(template_fix)

    # 2. Local LLM Repair (Qwen2.5-Coder via llama-server :8080)
    IF Config.REPAIR_PROVIDER == "llm":
        prompt = BuildRepairPrompt(finding, unit)
        response_json = LLMClient.PostChatCompletion(
            model="qwen2.5-coder-1.5b-instruct",
            messages=[
                {"role": "system", "content": SYSTEM_REPAIR_INSTRUCTIONS},
                {"role": "user", "content": prompt}
            ],
            temperature=0.15,
            max_tokens=1200
        )
        llm_fixes = ParseJsonFixes(response_json)
        candidates.EXTEND(llm_fixes)

    RETURN candidates


FUNCTION VerifyRepairs(finding, unit, candidates, test_runner):
    """
    Subject every candidate patch to static and dynamic verification gates.
    """
    verified_patches = []

    FOR EACH candidate IN candidates:
        patched_code = candidate.source
        checks = []

        # Gate 1: Syntax Validation
        parses_cleanly = CheckSyntax(patched_code, unit.language)
        checks.APPEND({"name": "Parses cleanly", "passed": parses_cleanly})

        IF NOT parses_cleanly:
            candidate.status = "rejected"
            candidate.checks = checks
            CONTINUE

        # Gate 2: Re-scan to verify original vulnerability is eliminated
        patched_unit = CopyWithNewSource(unit, patched_code)
        new_hits = DetectUnitWeaknesses(patched_unit)
        original_cwe_removed = NOT ANY(h.cwe == finding.cwe FOR h IN new_hits)
        checks.APPEND({"name": "Original weakness removed", "passed": original_cwe_removed})

        # Gate 3: Check for regressions (no new High or Critical vulnerabilities)
        new_high_risks = [h FOR h IN new_hits IF h.severity IN ["critical", "high"]]
        no_regressions = (len(new_high_risks) == 0)
        checks.APPEND({"name": "No new high-risk findings", "passed": no_regressions})

        # Gate 4: Function Signature & Contract Preservation
        same_signature = CompareFunctionSignatures(unit.signature, patched_code, unit.language)
        checks.APPEND({"name": "Signature preserved", "passed": same_signature})

        # Gate 5: Dynamic Test Execution (optional sandbox run)
        IF Config.RUN_TESTS AND test_runner.HasTests():
            test_result = test_runner.RunTestsWithPatch(unit.path, unit.source, patched_code)
            checks.APPEND({"name": "Project tests pass", "passed": test_result.passed})

        # Determine Recommendation Tier
        all_passed = ALL(c["passed"] FOR c IN checks)
        diff_unified = ComputeUnifiedDiff(unit.source, patched_code, unit.path)

        verified_patches.APPEND(PatchCandidate(
            diff=diff_unified,
            patched_source=patched_code,
            generator=candidate.generator,     # "template" or "llm"
            summary=candidate.summary,
            rationale=candidate.rationale,
            verified=all_passed,
            checks=checks,
            semantic_risk=candidate.semantic_risk OR (NOT same_signature)
        ))

    # Rank patches: Verified templates first, then verified LLM fixes
    RETURN SortPatchCandidates(verified_patches)
```

---

## 7. Background Job Runner & Persistence

```python
FUNCTION SubmitScanJob(scan_id, source_dict):
    """
    Dispatches scan execution to non-blocking thread pool.
    """
    ActiveScanRegistry.Register(scan_id)
    ThreadPool.Submit(ExecuteScanWorker, scan_id, source_dict)


FUNCTION ExecuteScanWorker(scan_id, source_dict):
    scan_record = Database.GetScan(scan_id)
    
    FUNCTION OnProgress(stage_name, percent_value):
        IF ActiveScanRegistry.IsCancelled(scan_id):
            RAISE ScanCancelledException()
        Database.UpdateScanProgress(scan_id, stage_name, percent_value)

    TRY:
        Database.SetScanStatus(scan_id, "running")
        RunScanPipeline(
            scan_job=scan_record,
            source_input=source_dict,
            progress_callback=OnProgress,
            cancel_check=LAMBDA: ActiveScanRegistry.IsCancelled(scan_id)
        )
        Database.SetScanStatus(scan_id, "completed")
    EXCEPT ScanCancelledException:
        Database.SetScanStatus(scan_id, "cancelled")
    EXCEPT Exception AS err:
        Database.SetScanStatus(scan_id, "failed", error_message=str(err))
    FINALLY:
        ActiveScanRegistry.Unregister(scan_id)
```
