---
name: cwe-78-command-injection
description: Detect and repair OS command injection through shells
cwe: CWE-78
owasp: A03:2021
targets: [detection, explanation, repair]
triggers: [os.system, popen, subprocess, shell=True, child_process.exec, Runtime.exec, ProcessBuilder]
---

# CWE-78 — OS Command Injection

## What it is
Untrusted input is interpreted by a system shell, so metacharacters (`;`, `&&`, `|`, `$()`,
backticks) run extra commands.

## How to spot it
- Python: `os.system`, `os.popen`, `subprocess.*(..., shell=True)`.
- Node: `child_process.exec` / `execSync` (they spawn a shell).
- Java: `Runtime.getRuntime().exec(String)` and `ProcessBuilder` with raw input.

## How to fix
- Pass an argument **list** and keep the shell off: `subprocess.run(["ping", "-c", "1", host], shell=False, check=True)`.
  `shell=False` does **not** stop option injection — validate `host` too.
- Avoid `shlex.split(user_input)` alone; it still allows argument injection.
- Validate against an allow-list and prefer library calls over shelling out.

## Explanation to give the developer
Show how the metacharacter reaches the shell and the argument-list rewrite (not just flipping
`shell=False`).
