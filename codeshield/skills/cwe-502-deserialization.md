---
name: cwe-502-deserialization
description: Detect and repair unsafe deserialization of untrusted data
cwe: CWE-502
owasp: A08:2021
targets: [detection, explanation, repair]
triggers: [pickle, marshal, dill, yaml.load, ObjectInputStream, readObject, unserialize]
---

# CWE-502 — Deserialization of Untrusted Data

## What it is
Deserialising attacker-controlled bytes can construct arbitrary objects, leading to remote code
execution.

## How to spot it
- Python: `pickle.load/loads`, `cPickle`, `marshal`, `dill`, `yaml.load` without `SafeLoader`.
- Java: `new ObjectInputStream(...).readObject()`.
- PHP/Node: `unserialize`, `node-serialize`.

## How to fix
- Move to a data-only format (JSON, MessagePack) with a schema.
- If YAML is required, use `yaml.safe_load`.
- If Java serialization is unavoidable, use an allow-list `ObjectInputFilter` and validate types.

## Explanation to give the developer
Show the gadget path in one sentence and the safe-format rewrite.
