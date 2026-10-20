"""Deterministic, language-aware repair templates."""
from __future__ import annotations

import ast
import difflib
import re
from dataclasses import dataclass
from typing import Optional

from ..schemas import CodeUnit, Finding


@dataclass
class TemplateFix:
    source: str
    summary: str
    rationale: str
    semantic_risk: bool = False
    generator: str = "template"


_MODULES = {
    "ast": "import ast", "json": "import json", "os": "import os",
    "subprocess": "import subprocess", "shlex": "import shlex", "secrets": "import secrets",
    "html": "import html",
}


def _line_index(unit: CodeUnit, absolute_line: int) -> Optional[int]:
    index = absolute_line - unit.start_line
    return index if 0 <= index < len(unit.source.splitlines()) else None


def _replace_line(unit: CodeUnit, line: int, new_line: str) -> Optional[str]:
    index = _line_index(unit, line)
    if index is None:
        return None
    lines = unit.source.splitlines()
    lines[index] = new_line
    return "\n".join(lines) + ("\n" if unit.source.endswith("\n") else "")


def _ensure_import(source: str, module: str) -> str:
    if re.search(rf"(?m)^\s*(?:import\s+{module}\b|from\s+{module}\s+import\b)", source):
        return source
    lines = source.splitlines()
    insert_at = 0
    indent = ""
    for index, line in enumerate(lines):
        if re.match(r"^\s*(?:async\s+)?def\s+\w+\s*\(", line):
            insert_at = index + 1
            indent = re.match(r"^(\s*)", line).group(1) + "    "
            if ":" not in line:
                for follow in range(index + 1, min(len(lines), index + 8)):
                    if ":" in lines[follow]:
                        insert_at = follow + 1
                        break
            break
        if re.match(r"^\s*(?:export\s+)?(?:async\s+)?function\b", line):
            return source
    statement = f"{indent}{_MODULES[module]}"
    lines.insert(insert_at, statement)
    return "\n".join(lines) + ("\n" if source.endswith("\n") else "")


def _driver_placeholder(unit: CodeUnit) -> tuple[str, bool]:
    source = unit.source
    if re.search(r"\bsqlite3\b", source):
        return "?", True
    if re.search(r"\b(psycopg2?|pymysql|mysql|asyncpg)\b", source):
        return "%s", True
    return "?", False


def _quote(value: str) -> str:
    return repr(value)


def _sql_fix(unit: CodeUnit, finding: Finding) -> Optional[TemplateFix]:
    try:
        tree = ast.parse(unit.source)
    except SyntaxError:
        return None
    values: dict[str, ast.AST] = {}
    for candidate in ast.walk(tree):
        if isinstance(candidate, (ast.Assign, ast.AnnAssign)):
            targets = candidate.targets if isinstance(candidate, ast.Assign) else [candidate.target]
            for target_node in targets:
                if isinstance(target_node, ast.Name) and candidate.value is not None:
                    values[target_node.id] = candidate.value
    target = finding.evidence[0].line if finding.evidence else finding.start_line
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        absolute = node.lineno + unit.start_line - 1
        if absolute != target or not node.args:
            continue
        if not isinstance(node.func, ast.Attribute) or node.func.attr not in {
            "execute", "executemany", "raw", "text",
        }:
            continue
        query_node = node.args[0]
        if isinstance(query_node, ast.Name):
            query_node = values.get(query_node.id, query_node)
        query, args = _decompose_sql(query_node)
        if not query or not args:
            continue
        placeholder, inferred = _driver_placeholder(unit)
        query = re.sub(r"%[sd]", placeholder, query)
        query = query.replace("\x00", placeholder)
        receiver = ast.get_source_segment(unit.source, node.func.value) or ""
        if not receiver:
            continue
        args_source = ", ".join(args)
        if len(args) == 1:
            args_source += ","
        replacement = f"{receiver}.{node.func.attr}({_quote(query)}, ({args_source}))"
        lines = unit.source.splitlines()
        if node.lineno != getattr(node, "end_lineno", node.lineno):
            continue
        line = lines[node.lineno - 1]
        updated = line[:node.col_offset] + replacement + line[node.end_col_offset:]
        lines[node.lineno - 1] = updated
        fixed = "\n".join(lines) + ("\n" if unit.source.endswith("\n") else "")
        return TemplateFix(
            source=fixed,
            summary="Parameterize the SQL query and bind the untrusted value",
            rationale="The query text is now constant and the value is passed to the driver as a bound parameter.",
            semantic_risk=not inferred,
        )
    return None


def _decompose_sql(node: ast.AST) -> tuple[str, list[str]]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value, []
    if isinstance(node, ast.JoinedStr):
        pieces: list[str] = []
        args: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                pieces.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                if pieces and pieces[-1].endswith(("'", '"')):
                    pieces[-1] = pieces[-1][:-1]
                pieces.append("\x00")
                args.append(ast.unparse(value.value))
        for index in range(len(pieces) - 1):
            if pieces[index] == "\x00" and pieces[index + 1].startswith(("'", '"')):
                pieces[index + 1] = pieces[index + 1][1:]
        return "".join(pieces), args
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
            right = node.right
            if isinstance(right, (ast.Tuple, ast.List)):
                return node.left.value, [ast.unparse(value) for value in right.elts]
            return node.left.value, [ast.unparse(right)]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, left_args = _decompose_sql(node.left)
        right, right_args = _decompose_sql(node.right)
        if left and right:
            return left + right, left_args + right_args
        if left and not right and isinstance(node.right, ast.Constant):
            return left + str(node.right.value), left_args
        if left:
            separator = " " if not left.endswith((" ", "\x00")) else ""
            return left + separator + "\x00", left_args + [ast.unparse(node.right)]
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        if isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str):
            query = node.func.value.value
            query = re.sub(r"\{[^{}]*\}", "\x00", query)
            return query, [ast.unparse(value) for value in node.args]
    return "", []


def _python_fix(unit: CodeUnit, finding: Finding) -> Optional[TemplateFix]:
    slug = finding.knowledge_ref or ""
    line = finding.evidence[0].line if finding.evidence else finding.start_line
    index = _line_index(unit, line)
    if index is None:
        return None
    lines = unit.source.splitlines()
    text = lines[index]
    if slug == "sql_injection":
        return _sql_fix(unit, finding)
    if slug == "code_injection":
        match = re.search(r"(?<![\w.])eval\s*\((.*)\)", text)
        if match:
            updated = text[:match.start()] + f"ast.literal_eval({match.group(1)})" + text[match.end():]
            fixed = _replace_line(unit, line, updated)
            if fixed:
                fixed = _ensure_import(fixed, "ast")
                return TemplateFix(
                    fixed, "Restrict evaluation to Python literals",
                    "ast.literal_eval parses only literal values and cannot execute arbitrary expressions.",
                    semantic_risk=True,
                )
        return None
    if slug == "command_injection":
        match = re.search(r"(?:os\.system|os\.popen)\s*\((.*)\)", text)
        if match:
            argument = match.group(1)
            updated = text[:match.start()] + f"subprocess.run(shlex.split({argument}), shell=False, check=False)" + text[match.end():]
            fixed = _replace_line(unit, line, updated)
            if fixed:
                fixed = _ensure_import(_ensure_import(fixed, "subprocess"), "shlex")
                return TemplateFix(
                    fixed, "Run the command without a shell",
                    "The command is split into arguments and executed directly, preventing shell metacharacter injection.",
                    semantic_risk=True,
                )
        if "shell=True" in text:
            updated = text.replace("shell=True", "shell=False")
            fixed = _replace_line(unit, line, updated)
            if fixed:
                return TemplateFix(
                    fixed, "Disable the shell",
                    "shell=False passes the existing argument vector directly to the child process.",
                    semantic_risk=True,
                )
        return None
    if slug == "hardcoded_secrets":
        match = re.search(r"([A-Za-z_][\w]*)\s*[:=]\s*([\"'])([^\"']{8,})\2", text)
        if match:
            variable = match.group(1)
            env_name = re.sub(r"[^A-Z0-9]+", "_", variable).strip("_").upper() or "SECRET"
            updated = text[:match.start()] + f"{variable} = os.environ[{env_name!r}]" + text[match.end():]
            fixed = _replace_line(unit, line, updated)
            if fixed:
                fixed = _ensure_import(fixed, "os")
                return TemplateFix(
                    fixed, f"Load the credential from {env_name}",
                    "The secret is removed from source and read from the process environment at runtime.",
                    semantic_risk=True,
                )
        return None
    if slug == "insecure_deserialization":
        if "pickle.loads" in text or "pickle.load" in text:
            updated = re.sub(r"pickle\.loads?\s*\(", "json.loads(", text, count=1)
            fixed = _replace_line(unit, line, updated)
            if fixed:
                fixed = _ensure_import(fixed, "json")
                return TemplateFix(
                    fixed, "Replace pickle with JSON",
                    "JSON is a data-only format and cannot instantiate arbitrary Python objects.",
                    semantic_risk=True,
                )
        if "yaml.load" in text:
            updated = text.replace("yaml.load", "yaml.safe_load", 1)
            fixed = _replace_line(unit, line, updated)
            if fixed:
                return TemplateFix(
                    fixed, "Use the safe YAML loader",
                    "safe_load rejects arbitrary Python object constructors.",
                    semantic_risk=True,
                )
        return None
    if slug == "insecure_tls":
        if "verify=False" in text:
            fixed = _replace_line(unit, line, text.replace("verify=False", "verify=True"))
            if fixed:
                return TemplateFix(fixed, "Enable TLS verification", "Certificate and hostname verification remain enabled.", False)
        return None
    if slug == "authentication_jwt":
        updated = re.sub(r"verify\s*=\s*False", "verify=True", text)
        updated = re.sub(r"['\"]verify_signature['\"]\s*:\s*False", "'verify_signature': True", updated)
        if updated != text:
            fixed = _replace_line(unit, line, updated)
            if fixed:
                return TemplateFix(fixed, "Enforce JWT signature verification", "The token signature is verified before claims are trusted.", False)
        return None
    if slug == "xss":
        if "Markup(" in text:
            updated = re.sub(r"(?:Markup|markupsafe\.Markup)\s*\((.*)\)", r"html.escape(\1)", text)
            fixed = _replace_line(unit, line, updated)
            if fixed:
                fixed = _ensure_import(fixed, "html")
                return TemplateFix(fixed, "Escape untrusted HTML", "html.escape neutralizes markup characters.", False)
        return None
    if slug == "path_traversal_lfi_rfi":
        match = re.search(r"((?:io\.)?open)\s*\((.*)\)", text)
        if match:
            argument = match.group(2)
            updated = text[:match.start()] + f"{match.group(1)}(os.path.basename({argument}))" + text[match.end():]
            fixed = _replace_line(unit, line, updated)
            if fixed:
                fixed = _ensure_import(fixed, "os")
                return TemplateFix(fixed, "Constrain the filename to a basename", "Traversal segments are removed before the filesystem call.", True)
        return None
    if slug == "weak_cryptography":
        if re.search(r"hashlib\.(md5|sha1)\s*\(", text):
            updated = re.sub(r"hashlib\.(md5|sha1)\s*\(", "hashlib.sha256(", text)
            fixed = _replace_line(unit, line, updated)
            if fixed:
                return TemplateFix(fixed, "Use SHA-256", "SHA-256 is collision-resistant for integrity and fingerprinting.", True)
        return None
    if slug == "security_misconfiguration":
        if re.search(r"DEBUG\s*=\s*True", text):
            fixed = _replace_line(unit, line, text.replace("DEBUG = True", "DEBUG = False"))
            if fixed:
                return TemplateFix(fixed, "Disable debug mode", "Production errors no longer expose stack traces or the debugger.", False)
        if "debug=True" in text:
            fixed = _replace_line(unit, line, text.replace("debug=True", "debug=False"))
            if fixed:
                return TemplateFix(fixed, "Disable debug mode", "Production errors no longer expose stack traces or the debugger.", False)
        return None
    return None


def _js_fix(unit: CodeUnit, finding: Finding) -> Optional[TemplateFix]:
    slug = finding.knowledge_ref or ""
    line = finding.evidence[0].line if finding.evidence else finding.start_line
    index = _line_index(unit, line)
    if index is None:
        return None
    text = unit.source.splitlines()[index]
    if slug == "xss" and re.search(r"\.innerHTML\s*=", text):
        fixed = _replace_line(unit, line, re.sub(r"\.innerHTML(\s*=)", ".textContent\\1", text))
        if fixed:
            return TemplateFix(fixed, "Assign text instead of HTML", "textContent treats the value as text and does not parse markup.", True)
    if slug == "hardcoded_secrets":
        match = re.search(r"(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*[:=]\s*([\"'])([^\"']{8,})\2", text)
        if match:
            variable = match.group(1)
            env_name = re.sub(r"[^A-Za-z0-9]+", "_", variable).upper()
            updated = text[:match.start()] + f"{variable} = process.env.{env_name}" + text[match.end():]
            fixed = _replace_line(unit, line, updated)
            if fixed:
                return TemplateFix(fixed, f"Load the credential from {env_name}", "The secret is removed from source and read from the environment.", True)
    if slug == "insecure_tls" and "rejectUnauthorized" in text:
        updated = re.sub(r"(rejectUnauthorized\s*:\s*)false", r"\1true", text)
        fixed = _replace_line(unit, line, updated)
        if fixed:
            return TemplateFix(fixed, "Enable TLS verification", "Certificate validation is no longer disabled.", False)
    if slug == "weak_cryptography":
        updated = re.sub(r"createHash\(\s*(['\"])(?:md5|sha1)\1\s*\)", "createHash('sha256')", text, flags=re.IGNORECASE)
        if updated != text:
            fixed = _replace_line(unit, line, updated)
            if fixed:
                return TemplateFix(fixed, "Use SHA-256", "SHA-256 replaces a broken hash algorithm.", True)
    if slug == "sql_injection":
        match = re.search(
            r"([A-Za-z_$][\w$.]*\.(?:query|execute))\s*\(\s*(['\"])(.*?)\2\s*\+\s*([A-Za-z_$][\w$]*)\s*\)",
            text,
        )
        if match:
            call, quote_char, prefix, variable = match.groups()
            query = prefix.rstrip() + " ?"
            updated = text[:match.start()] + f"{call}({quote_char}{query}{quote_char}, [{variable}])" + text[match.end():]
            fixed = _replace_line(unit, line, updated)
            if fixed:
                return TemplateFix(fixed, "Bind the SQL value", "The query text is constant and the value is bound separately.", True)
    if slug == "security_misconfiguration" and re.search(r"DEBUG\s*[:=]\s*true", text, re.IGNORECASE):
        fixed = _replace_line(unit, line, re.sub(r"(DEBUG\s*[:=]\s*)true", r"\1false", text, flags=re.IGNORECASE))
        if fixed:
            return TemplateFix(fixed, "Disable debug mode", "Production errors no longer expose diagnostics.", False)
    return None


def _java_fix(unit: CodeUnit, finding: Finding) -> Optional[TemplateFix]:
    slug = finding.knowledge_ref or ""
    line = finding.evidence[0].line if finding.evidence else finding.start_line
    index = _line_index(unit, line)
    if index is None:
        return None
    text = unit.source.splitlines()[index]
    if slug == "hardcoded_secrets":
        match = re.search(r"([A-Za-z_][\w]*)\s*=\s*([\"'])([^\"']{8,})\2", text)
        if match:
            variable = match.group(1)
            env_name = re.sub(r"[^A-Za-z0-9]+", "_", variable).upper()
            updated = text[:match.start()] + f'{variable} = System.getenv("{env_name}")' + text[match.end():]
            fixed = _replace_line(unit, line, updated)
            if fixed:
                return TemplateFix(fixed, f"Load the credential from {env_name}", "The secret is read from the process environment.", True)
    if slug == "weak_cryptography" and re.search(r'getInstance\(\s*"(MD5|SHA-?1)"', text, re.I):
        fixed = _replace_line(unit, line, re.sub(r'"(MD5|SHA-?1)"', '"SHA-256"', text, flags=re.IGNORECASE))
        if fixed:
            return TemplateFix(fixed, "Use SHA-256", "SHA-256 replaces a broken digest algorithm.", True)
    if slug == "security_misconfiguration" and re.search(r"debug\s*=\s*true", text, re.IGNORECASE):
        fixed = _replace_line(unit, line, re.sub(r"(debug\s*=\s*)true", r"\1false", text, flags=re.IGNORECASE))
        if fixed:
            return TemplateFix(fixed, "Disable debug mode", "Production errors no longer expose diagnostics.", False)
    return None


def templates_for(finding: Finding, unit: CodeUnit) -> list[TemplateFix]:
    fix: Optional[TemplateFix] = None
    if unit.language == "python":
        fix = _python_fix(unit, finding)
    elif unit.language in {"javascript", "typescript", "tsx"}:
        fix = _js_fix(unit, finding)
    elif unit.language == "java":
        fix = _java_fix(unit, finding)
    if fix is None or fix.source == unit.source:
        return []
    fix.source = fix.source.rstrip("\n") + "\n"
    return [fix]


def unified_diff(original: str, patched: str, path: str) -> str:
    original_lines = [line + "\n" for line in original.splitlines()]
    patched_lines = [line + "\n" for line in patched.splitlines()]
    return "".join(
        difflib.unified_diff(
            original_lines, patched_lines,
            fromfile=f"a/{path}", tofile=f"b/{path}", n=3,
        )
    )
