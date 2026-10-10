---
name: cwe-89-sql-injection
description: Detect and repair SQL injection built from string interpolation or concatenation
cwe: CWE-89
owasp: A03:2021
targets: [detection, explanation, repair]
triggers: [execute, executemany, query, SELECT, INSERT, UPDATE, DELETE, f-string, cursor]
---

# CWE-89 — SQL Injection

## What it is
Untrusted input changes the structure of a SQL statement rather than only its data.

## How to spot it
- `cursor.execute(f"...{var}...")`, `"...".format(var)`, `"..." % var`, or `"..." + var`.
- ORM escape hatches (`raw()`, `text()`, `extra()`) with interpolation.
- Java `Statement.execute("... " + param)`; JS template literals passed to a query client.

## How to confirm (SAST)
Trace the flagged value back to a request/CLI/file source. If it is a literal, it is a false
positive.

## How to fix
- Parameterise: `cursor.execute("SELECT ... WHERE name = ?", (name,))`.
- Named placeholders for readability; never rebuild identifiers from input — validate table/
  column names against an allow-list.
- For dynamic `ORDER BY`, map user input to a fixed set of column names.

## Explanation to give the developer
Name the concat/format site as the root cause, cite the request source that reaches it, and
show the parameterised rewrite.
