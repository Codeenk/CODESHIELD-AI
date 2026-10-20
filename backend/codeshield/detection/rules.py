"""Precision-first static rules with AST checks for Python and targeted checks for JS/TS/Java."""
from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable, Optional

from .. import config
from ..schemas import CodeUnit

_SQL = re.compile(
    r"\b(select|insert|update|delete|replace|merge|create|alter|drop|truncate|with|call|exec)\b",
    re.IGNORECASE,
)
_SECRET_NAME = re.compile(
    r"(?i)^(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|secret[_-]?key"
    r"|private[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|token|client[_-]?secret"
    r"|credentials?|passphrase|[a-z0-9_]+[_-](password|secret|api[_-]?key|token))$"
)
_SECRET_EXCLUDE = re.compile(
    r"(?i)(token[_-]?(type|url|prefix|header|endpoint|expiry|ttl)|max[_-]?tokens"
    r"|tokenizer|secret[_-]?name|password[_-]?field|password[_-]?hash|hashed[_-]?password"
    r"|password[_-]?(min|max)|secret[_-]?key[_-]?path)"
)
_PLACEHOLDER = re.compile(
    r"(?i)^(<.*>|\{\{.*\}\}|your[_-].*|change[_-]?me|example.*|placeholder|dummy|xxx+|test|"
    r"replace[_-]?me|todo|none|null|true|false)$"
)

_JS_TAINT_SOURCE = re.compile(
    r"\b(req(?:uest)?\.(?:body|query|params|headers|cookies)|location\.(?:search|hash|href)"
    r"|window\.location|document\.(?:URL|documentURI|cookie)|process\.argv|event\.target\.value"
    r"|event\.currentTarget\.value|new URLSearchParams\(location)"
)
_PY_TAINT_SOURCE = re.compile(
    r"\b(request\.(?:args|form|json|values|cookies|headers|body|query_params|path_params|files)"
    r"|req\.(?:body|query|params)|input\(|sys\.argv|event\.(?:body|queryStringParameters)"
    r"|event\.get\()"
)


@lru_cache(maxsize=1)
def _mapping() -> dict[str, dict[str, str]]:
    path = config.KNOWLEDGE_DIR / "mapping.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def rule_meta(slug: str) -> dict[str, str]:
    data = _mapping()
    merged = dict(data.get("__default__", {}))
    merged.update(data.get(slug, {}))
    merged.setdefault("cwe", "CWE-693")
    merged.setdefault("cwe_title", "Protection Mechanism Failure")
    merged.setdefault("owasp", "")
    merged.setdefault("severity", "medium")
    return merged


@dataclass
class RuleHit:
    slug: str
    line: int
    reason: str
    confidence: float
    message: str = ""
    snippet: str = ""
    weight: float = 1.0

    @property
    def meta(self) -> dict[str, str]:
        return rule_meta(self.slug)


@dataclass
class _Imports:
    mapping: dict[str, str]

    @classmethod
    def from_tree(cls, tree: ast.AST) -> "_Imports":
        mapping: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        mapping[alias.asname] = alias.name
                    else:
                        mapping[alias.name.split(".")[0]] = alias.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    mapping[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        return cls(mapping)

    def full_name(self, node: ast.AST, depth: int = 0) -> str:
        if depth > 8:
            return ""
        if isinstance(node, ast.Name):
            return self.mapping.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.full_name(node.value, depth + 1)
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, ast.Call):
            return self.full_name(node.func, depth + 1)
        return ""


def _param_names(unit: CodeUnit, tree: ast.AST) -> set[str]:
    names: set[str] = set()
    if unit.kind != "function":
        return names
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
                if arg.arg in {"self", "cls"}:
                    continue
                annotation = ast.unparse(arg.annotation) if arg.annotation is not None else ""
                # A Path-annotated parameter is an internal, already-resolved
                # contract (CLI tools, pipeline helpers), not a raw request value.
                if annotation.endswith("Path"):
                    continue
                names.add(arg.arg)
            if node.args.vararg:
                names.add(node.args.vararg.arg)
            if node.args.kwarg:
                names.add(node.args.kwarg.arg)
            break
    return names


def _assigned_names(node: ast.AST) -> list[str]:
    targets: list[ast.AST] = []
    if isinstance(node, ast.Assign):
        targets = list(node.targets)
    elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
        targets = [node.target]
    names: list[str] = []
    for target in targets:
        if isinstance(target, ast.Name):
            names.append(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            names.extend(t.id for t in target.elts if isinstance(t, ast.Name))
    return names


_SANITIZERS = {
    "os.path.basename", "werkzeug.utils.secure_filename", "pathlib.Path.name",
    "shlex.quote", "pipes.quote", "html.escape", "markupsafe.escape", "bleach.clean",
    "int", "float", "uuid.UUID", "secrets.compare_digest", "hmac.compare_digest",
    "_safe_relative", "_safe_join", "_safe_path", "safe_relative", "safe_join",
}


def _is_tainted(node: ast.AST, tainted: set[str], imports: _Imports) -> bool:
    if isinstance(node, ast.Name):
        return node.id in tainted
    if isinstance(node, ast.Constant):
        return False
    if isinstance(node, ast.JoinedStr):
        return any(_is_tainted(v, tainted, imports) for v in node.values)
    if isinstance(node, ast.FormattedValue):
        return _is_tainted(node.value, tainted, imports)
    if isinstance(node, ast.BinOp):
        return _is_tainted(node.left, tainted, imports) or _is_tainted(node.right, tainted, imports)
    if isinstance(node, ast.BoolOp):
        return any(_is_tainted(v, tainted, imports) for v in node.values)
    if isinstance(node, ast.IfExp):
        return _is_tainted(node.body, tainted, imports) or _is_tainted(node.orelse, tainted, imports)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(_is_tainted(e, tainted, imports) for e in node.elts)
    if isinstance(node, ast.Dict):
        return any(_is_tainted(k, tainted, imports) for k in node.keys if k) or any(
            _is_tainted(v, tainted, imports) for v in node.values
        )
    if isinstance(node, ast.Subscript):
        return _is_tainted(node.value, tainted, imports)
    if isinstance(node, ast.Attribute):
        return _is_tainted(node.value, tainted, imports)
    if isinstance(node, ast.Call):
        name = imports.full_name(node.func)
        if name in _SANITIZERS or name.split(".")[-1] in {"basename", "secure_filename"}:
            return False
        if name.endswith("parse_args"):
            return False
        source = _PY_TAINT_SOURCE.search(ast.unparse(node) if hasattr(ast, "unparse") else "")
        if source:
            return True
        return any(_is_tainted(arg, tainted, imports) for arg in node.args)
    if isinstance(node, ast.Starred):
        return _is_tainted(node.value, tainted, imports)
    return False


def _guarded_names(tree: ast.AST) -> set[str]:
    """Names proven safe by a containment or format check in this unit.

    Recognizes ``path.is_relative_to(base)``, ``path.resolve().parents``,
    ``os.path.commonpath(...)``, and strict regex validation such as
    ``re.fullmatch(pattern, name)`` or ``_SLUG.match(name)``.
    """
    guarded: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        for test in _iter_test_nodes(node.test):
            guarded.update(_guard_subjects(test))
    return guarded


def _iter_test_nodes(node: ast.AST) -> Iterable[ast.AST]:
    if isinstance(node, ast.BoolOp):
        for value in node.values:
            yield from _iter_test_nodes(value)
    elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        yield from _iter_test_nodes(node.operand)
    else:
        yield node


def _guard_subjects(test: ast.AST) -> set[str]:
    subjects: set[str] = set()
    if isinstance(test, ast.Compare):
        for op, comparator in zip(test.ops, test.comparators):
            if not isinstance(op, ast.In):
                continue
            left_text = _text_of(test.left)
            right_text = _text_of(comparator)
            if "resolve(" in right_text or "realpath(" in right_text:
                subjects.update(_names_of(comparator))
            elif "resolve(" in left_text or "realpath(" in left_text:
                subjects.update(_names_of(test.left))
            elif "parents" in right_text or "startswith(" in right_text:
                subjects.update(_names_of(test.left))
    if isinstance(test, ast.Call):
        func = test.func
        attr = getattr(func, "attr", "")
        if attr in {"is_relative_to", "resolve", "realpath"}:
            subjects.update(_names_of(func.value))
        if attr == "startswith":
            subjects.update(_names_of(func.value))
        if attr in {"match", "fullmatch", "search"} and len(test.args) >= 2:
            subjects.update(_names_of(test.args[1]))
        if attr in {"fullmatch", "match"} and len(test.args) == 1:
            subjects.update(_names_of(test.args[0]))
    return subjects


def _text_of(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _names_of(node: ast.AST) -> set[str]:
    return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}


def _collect_taint(tree: ast.AST, initial: set[str], imports: _Imports) -> set[str]:
    tainted = set(initial)
    for _ in range(8):
        changed = False
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
                value = getattr(node, "value", None)
                if value is not None and _is_tainted(value, tainted, imports):
                    for name in _assigned_names(node):
                        if name not in tainted:
                            tainted.add(name)
                            changed = True
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                if _is_tainted(node.iter, tainted, imports):
                    for target in ast.walk(node.target):
                        if isinstance(target, ast.Name) and target.id not in tainted:
                            tainted.add(target.id)
                            changed = True
            elif isinstance(node, ast.comprehension):
                if _is_tainted(node.iter, tainted, imports):
                    for target in ast.walk(node.target):
                        if isinstance(target, ast.Name) and target.id not in tainted:
                            tainted.add(target.id)
                            changed = True
        if not changed:
            break
    return tainted


def _dynamic(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return False
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp):
        return isinstance(node.op, (ast.Add, ast.Mod))
    if isinstance(node, ast.Call):
        name = getattr(node.func, "attr", "") or getattr(node.func, "id", "")
        return name in {"format", "join", "replace", "concat", "text", "raw"}
    return True


def _static_text(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
    if isinstance(node, ast.BinOp):
        return _static_text(node.left) + " " + _static_text(node.right)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return _static_text(node.func.value)
    return ""


def _assignments(tree: ast.AST) -> dict[str, ast.AST]:
    values: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            value = getattr(node, "value", None)
            if value is None:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    values[target.id] = value
    return values


def _static_text_deep(node: ast.AST, values: dict[str, ast.AST], depth: int = 0) -> str:
    if depth > 6:
        return ""
    if isinstance(node, ast.Name):
        assigned = values.get(node.id)
        return _static_text_deep(assigned, values, depth + 1) if assigned is not None else ""
    if isinstance(node, ast.BinOp):
        return _static_text_deep(node.left, values, depth + 1) + " " + _static_text_deep(node.right, values, depth + 1)
    if isinstance(node, ast.JoinedStr):
        return "".join(
            value.value if isinstance(value, ast.Constant) and isinstance(value.value, str)
            else _static_text_deep(value.value, values, depth + 1) if isinstance(value, ast.FormattedValue)
            else "" for value in node.values
        )
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format":
            return _static_text_deep(node.func.value, values, depth + 1)
        if node.func.attr in {"replace", "join", "concat"}:
            return _static_text_deep(node.func.value, values, depth + 1)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return _static_text(node)


def _sql_names(tree: ast.AST) -> set[str]:
    values = _assignments(tree)
    names: set[str] = set()
    for name, value in values.items():
        if _SQL.search(_static_text_deep(value, values)):
            names.add(name)
    return names


def _line_text(unit: CodeUnit, line: int) -> str:
    lines = unit.source.splitlines()
    relative = line - unit.start_line
    if 0 <= relative < len(lines):
        return lines[relative].strip()[:400]
    return ""


class _PyVisitor(ast.NodeVisitor):
    def __init__(
        self, unit: CodeUnit, imports: _Imports, tainted: set[str],
        sql_names: Optional[set[str]] = None,
    ) -> None:
        self.unit = unit
        self.imports = imports
        self.tainted = tainted
        self.sql_names = sql_names or set()
        self.hits: list[RuleHit] = []

    def add(self, slug: str, node: ast.AST, reason: str, confidence: float, message: str = "") -> None:
        line = getattr(node, "lineno", 1) + self.unit.start_line - 1
        self.hits.append(
            RuleHit(
                slug=slug, line=line, reason=reason, confidence=confidence,
                message=message, snippet=_line_text(self.unit, line),
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        name = self.imports.full_name(node.func)
        short = name.split(".")[-1]
        args = node.args
        tainted_args = [a for a in args if _is_tainted(a, self.tainted, self.imports)]
        first_tainted = bool(args and _is_tainted(args[0], self.tainted, self.imports))

        if name in {"eval", "exec", "compile"} and args:
            if _is_tainted(args[0], self.tainted, self.imports) or not isinstance(args[0], ast.Constant):
                self.add("code_injection", node, f"Untrusted data reaches builtin {name}()", 0.95,
                         "Dynamic code evaluation enables arbitrary code execution.")
        if name in {"os.system", "os.popen", "commands.getoutput", "commands.getstatusoutput", "platform.popen"}:
            if first_tainted or not isinstance(args[0], ast.Constant) if args else False:
                self.add("command_injection", node, f"Untrusted data reaches {name}()", 0.95,
                         "Shell metacharacters can execute arbitrary commands on the host.")
        if short in {"run", "call", "check_call", "check_output", "Popen"} and "subprocess" in name:
            shell_true = any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
            if shell_true and first_tainted:
                self.add("command_injection", node, "subprocess invoked with shell=True on untrusted input", 0.92,
                         "A shell interprets metacharacters in untrusted input.")
        if name in {"os.execv", "os.execve", "os.execl", "os.spawnl", "os.spawnv"} and first_tainted:
            self.add("command_injection", node, f"Untrusted data reaches {name}()", 0.85)

        if name in {"pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads", "dill.load",
                    "dill.loads", "marshal.load", "marshal.loads", "yaml.unsafe_load"}:
            self.add("insecure_deserialization", node, f"Unsafe deserialization via {name}()", 0.9,
                     "Deserializing untrusted bytes can execute arbitrary code.")
        if name == "yaml.load":
            safe_loader = any(
                kw.arg == "Loader" and "SafeLoader" in self.imports.full_name(kw.value)
                for kw in node.keywords
            )
            safe_loader = safe_loader or any(
                "SafeLoader" in self.imports.full_name(a) for a in args[1:2]
            )
            if not safe_loader:
                self.add("insecure_deserialization", node, "yaml.load() without a safe loader", 0.85,
                         "Use yaml.safe_load() for untrusted documents.")

        if short in {"execute", "executemany", "raw", "extra", "text", "from_statement"} or name.endswith(".execute"):
            if args and _dynamic(args[0]) and first_tainted:
                literal = isinstance(args[0], ast.Name) and args[0].id in self.sql_names
                if literal or _SQL.search(_static_text(args[0])):
                    self.add("sql_injection", node, "Untrusted input is interpolated into a SQL query", 0.9,
                             "Use parameterized queries with bound values.")
        if name in {"sqlalchemy.text", "text"} and args and _dynamic(args[0]) and first_tainted:
            if _SQL.search(_static_text(args[0])):
                self.add("sql_injection", node, "Untrusted input is interpolated into a SQLAlchemy text() query", 0.88)

        if name in {"requests.get", "requests.post", "requests.put", "requests.delete", "requests.head",
                    "requests.patch", "requests.request", "httpx.get", "httpx.post", "httpx.put",
                    "httpx.delete", "httpx.patch", "httpx.request", "urllib.request.urlopen", "urlopen"}:
            if first_tainted and _url_like(args[0], self.imports):
                self.add("ssrf", node, "Untrusted input controls an outbound request URL", 0.82,
                         "Validate the destination against a strict allowlist.")
        if name in {"flask.redirect", "redirect", "django.shortcuts.redirect", "HttpResponseRedirect"}:
            if first_tainted:
                self.add("open_redirect", node, "Untrusted input controls a redirect target", 0.8,
                         "Only redirect to validated relative paths or an allowlist.")

        if short in {"render_template_string", "Template"} and first_tainted:
            self.add("ssti", node, "Untrusted input reaches a server-side template", 0.9,
                     "Never build templates from user input.")
        if isinstance(node.func, ast.Attribute) and node.func.attr == "render":
            receiver = node.func.value
            if isinstance(receiver, ast.Call) and _is_tainted(receiver, self.tainted, self.imports):
                self.add("ssti", node, "Untrusted input reaches a server-side template render", 0.85)

        if name in {"open", "io.open", "codecs.open", "os.open", "os.remove", "os.unlink", "os.rename",
                    "shutil.copy", "shutil.copyfile", "shutil.move", "send_file", "FileResponse"}:
            if first_tainted:
                self.add("path_traversal_lfi_rfi", node, "Untrusted input reaches a filesystem path", 0.8,
                         "Resolve the path and enforce a fixed base directory.")
        if isinstance(node.func, ast.Attribute) and node.func.attr in {
            "read_text", "read_bytes", "write_text", "write_bytes", "open",
        } and _is_tainted(node.func.value, self.tainted, self.imports):
            if node.func.attr == "open" and isinstance(node.func.value, ast.Name) and node.func.value.id in {
                "archive", "zip", "tar", "archive_file",
            }:
                self.generic_visit(node)
                return
            self.add("path_traversal_lfi_rfi", node, "Untrusted input constructs a filesystem path", 0.75)

        xml_roots = ("xml.", "lxml.", "xml.etree", "ElementTree", "defusedxml")
        if short in {"parse", "fromstring", "parseString", "XML", "iterparse", "XMLParser"} and any(
            xml_roots in name for xml_roots in ("xml.", "lxml.", "ElementTree")
        ):
            if first_tainted:
                self.add("xxe", node, "Untrusted XML is parsed without entity hardening", 0.78,
                         "Use defusedxml or disable external entities.")

        if name in {"hashlib.md5", "hashlib.sha1"}:
            self.add("weak_cryptography", node, f"Weak hash function {name}()", 0.55,
                     "Use SHA-256 or stronger for security-sensitive hashing.")
        if name in {"random.random", "random.choice", "random.randint", "random.randrange", "random.getrandbits"}:
            self.add("insecure_randomness", node, "Non-cryptographic randomness", 0.45,
                     "Use the secrets module for tokens and codes.")
        if name in {"tempfile.mktemp"}:
            self.add("security_misconfiguration", node, "tempfile.mktemp() is race-prone", 0.6,
                     "Use tempfile.mkstemp() or NamedTemporaryFile().")

        if short in {"get", "post", "put", "delete", "patch"} and any(
            kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False
            for kw in node.keywords
        ):
            self.add("insecure_tls", node, "TLS certificate verification is disabled", 0.85,
                     "Keep certificate verification enabled.")
        if name in {"jwt.decode", "jws.verify"}:
            for kw in node.keywords:
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    self.add("authentication_jwt", node, "JWT signature verification is disabled", 0.92)
                if kw.arg == "options" and isinstance(kw.value, ast.Dict):
                    for key, value in zip(kw.value.keys, kw.value.values):
                        if isinstance(key, ast.Constant) and key.value == "verify_signature" and isinstance(value, ast.Constant) and value.value is False:
                            self.add("authentication_jwt", node, "JWT signature verification is disabled", 0.92)
        if name in {"xml.etree.ElementTree.parse", "lxml.etree.parse"} and first_tainted:
            self.add("xxe", node, "Untrusted XML is parsed", 0.75)

        if short == "Markup" and first_tainted:
            self.add("xss", node, "Untrusted input is marked as safe HTML", 0.85)
        if short in {"HttpResponse", "Response"} and first_tainted:
            if any(
                kw.arg == "mimetype" and isinstance(kw.value, ast.Constant)
                and "html" in str(kw.value.value)
                for kw in node.keywords
            ) or name == "HttpResponse":
                self.add("xss", node, "Untrusted input is rendered into an HTML response", 0.65)

        if name in {"collection.find", "collection.find_one", "db.find", "db.find_one"} and args:
            if isinstance(args[0], ast.Dict) and _is_tainted(args[0], self.tainted, self.imports):
                self.add("nosql_injection", node, "Untrusted object is used directly as a NoSQL filter", 0.8)
            if _is_tainted(args[0], self.tainted, self.imports) and not isinstance(args[0], ast.Dict):
                self.add("nosql_injection", node, "Untrusted data is used as a NoSQL filter", 0.7)

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._check_secret(node.targets, node.value, node)
        self._check_debug(node.targets, node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._check_secret([node.target], node.value, node)
            self._check_debug([node.target], node.value, node)
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        for key, value in zip(node.keys, node.values):
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                if _SECRET_NAME.match(key.value) and not _SECRET_EXCLUDE.search(key.value):
                    if isinstance(value, ast.Constant) and isinstance(value.value, str):
                        self._secret_hit(key.value, value, node)
        self.generic_visit(node)

    def _check_secret(self, targets: list[ast.AST], value: ast.AST, node: ast.AST) -> None:
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return
        for target in targets:
            name = ""
            if isinstance(target, ast.Name):
                name = target.id
            elif isinstance(target, ast.Attribute):
                name = target.attr
            if not name or not _SECRET_NAME.match(name) or _SECRET_EXCLUDE.search(name):
                continue
            self._secret_hit(name, value, node)

    def _secret_hit(self, name: str, value: ast.Constant, node: ast.AST) -> None:
        text = str(value.value)
        if len(text) < 8 or _PLACEHOLDER.match(text):
            return
        if text.startswith(("http://", "https://")) and name.lower().endswith(("url", "endpoint")):
            return
        confidence = 0.88 if re.search(r"(?i)(password|secret|api[_-]?key|private[_-]?key)", name) else 0.78
        self.add("hardcoded_secrets", node, f"Hardcoded credential assigned to {name}", confidence,
                 "Load secrets from a secret manager or environment at runtime.")

    def _check_debug(self, targets: list[ast.AST], value: ast.AST, node: ast.AST) -> None:
        if not isinstance(value, ast.Constant) or value.value is not True:
            return
        for target in targets:
            name = target.id if isinstance(target, ast.Name) else getattr(target, "attr", "")
            if name.upper() == "DEBUG":
                self.add("security_misconfiguration", node, "Debug mode enabled", 0.7,
                         "Disable debug mode in production.")

    def visit_Constant(self, node: ast.Constant) -> None:
        self.generic_visit(node)


def _url_like(node: ast.AST, imports: _Imports) -> bool:
    if isinstance(node, ast.Name):
        return bool(re.search(r"(?i)(url|uri|host|endpoint|target|callback|webhook)", node.id))
    if isinstance(node, ast.JoinedStr):
        return "http" in _static_text(node).lower() or any(
            _url_like(v.value, imports) for v in node.values if isinstance(v, ast.FormattedValue)
        )
    if isinstance(node, ast.BinOp):
        return "http" in _static_text(node).lower() or _url_like(node.left, imports) or _url_like(node.right, imports)
    if isinstance(node, ast.Call):
        name = imports.full_name(node.func)
        if _PY_TAINT_SOURCE.search(ast.unparse(node)):
            return True
        if re.search(r"(?i)(url|uri|host|endpoint|callback|webhook)", name):
            return True
        return any(_url_like(arg, imports) for arg in node.args)
    if isinstance(node, ast.Subscript):
        return _url_like(node.value, imports)
    if isinstance(node, ast.Attribute):
        return _url_like(node.value, imports) or bool(re.search(r"(?i)(url|uri|host)", node.attr))
    return False


def _scan_python(unit: CodeUnit) -> list[RuleHit]:
    try:
        tree = ast.parse(unit.source)
    except SyntaxError:
        return _scan_regex_generic(unit)
    imports = _Imports.from_tree(tree)
    guarded = _guarded_names(tree)
    tainted = _collect_taint(tree, _param_names(unit, tree) - guarded, imports)
    tainted -= guarded
    visitor = _PyVisitor(unit, imports, tainted, _sql_names(tree))
    visitor.visit(tree)
    return visitor.hits


def _py_fallback(unit: CodeUnit) -> list[RuleHit]:
    hits: list[RuleHit] = []
    for index, line in enumerate(unit.source.splitlines()):
        if re.search(r"(?<![\w.])eval\s*\(|(?<![\w.])exec\s*\(", line):
            hits.append(RuleHit("code_injection", unit.start_line + index, "Dynamic code evaluation", 0.7, snippet=line.strip()[:400]))
        if re.search(r"\b(os\.system|pickle\.loads?|yaml\.load)\s*\(", line):
            hits.append(RuleHit("command_injection", unit.start_line + index, "Unsafe call on untrusted input", 0.6, snippet=line.strip()[:400]))
    return hits


def _scan_regex_generic(unit: CodeUnit) -> list[RuleHit]:
    hits: list[RuleHit] = []
    for index, line in enumerate(unit.source.splitlines()):
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "#", "*", "/*")):
            continue
        line_no = unit.start_line + index
        secret = _regex_secret(stripped)
        if secret:
            hits.append(RuleHit("hardcoded_secrets", line_no, secret, 0.72, snippet=stripped[:400]))
        if _SQL.search(stripped) and re.search(r"(?i)(query|execute|raw|prepare)\s*\(", stripped) and (
            "${" in stripped or re.search(r"[\"']\s*\+\s*\w", stripped)
        ):
            hits.append(RuleHit("sql_injection", line_no, "SQL query assembled with string concatenation", 0.7, snippet=stripped[:400]))
    return hits


def _regex_secret(line: str) -> Optional[str]:
    match = re.search(
        r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token"
        r"|client[_-]?secret|private[_-]?key)\b\s*[:=]\s*([\"'])([^\"']{8,})\2",
        line,
    )
    if not match:
        return None
    name, _, value = match.groups()
    if _SECRET_EXCLUDE.search(name) or _PLACEHOLDER.match(value) or "${" in value:
        return None
    return f"Hardcoded credential assigned to {name}"


def _signature_params(unit: CodeUnit) -> set[str]:
    text = unit.signature
    match = re.search(r"\(([^)]*)\)", text)
    if not match:
        return set()
    params: set[str] = set()
    depth = 0
    current = ""
    chunks = []
    for char in match.group(1):
        if char in "<([{":
            depth += 1
        elif char in ">)]}":
            depth = max(0, depth - 1)
        if char == "," and depth == 0:
            chunks.append(current)
            current = ""
        else:
            current += char
    chunks.append(current)
    for chunk in chunks:
        chunk = chunk.split("=")[0].split(":")[0].strip()
        if chunk.startswith("..."):
            chunk = chunk[3:]
        identifiers = re.findall(r"[A-Za-z_$][\w$]*", chunk)
        if identifiers:
            name = identifiers[-1]
            if name not in {"self", "this", "String", "int", "long", "boolean", "double", "float"}:
                params.add(name)
    return params


def _scan_js_java(unit: CodeUnit) -> list[RuleHit]:
    hits: list[RuleHit] = []
    tainted = _signature_params(unit)
    language = unit.language
    for index, raw in enumerate(unit.source.splitlines()):
        line = raw.strip()
        line_no = unit.start_line + index
        if not line or line.startswith(("//", "*", "/*", "#")):
            continue

        secret = _regex_secret(line)
        if secret:
            hits.append(RuleHit("hardcoded_secrets", line_no, secret, 0.72, snippet=line[:400]))

        assignment = re.match(
            r"(?:(?:const|let|var|final|String|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*(.+)$", line
        )
        if assignment:
            name, rhs = assignment.groups()
            if _js_tainted(rhs, tainted):
                tainted.add(name)

        if _js_tainted(line, tainted) or _JS_TAINT_SOURCE.search(line):
            _js_sinks(hits, line, line_no, tainted, language)

        if language == "java":
            if re.search(r"MessageDigest\.getInstance\(\s*\"(MD5|SHA-?1)\"", line, re.I):
                hits.append(RuleHit("weak_cryptography", line_no, "Weak digest algorithm", 0.65, snippet=line[:400]))
            if re.search(r"new\s+File\s*\([^)]*\+", line) and _js_tainted(line, tainted):
                hits.append(RuleHit("path_traversal_lfi_rfi", line_no, "Untrusted input constructs a file path", 0.72, snippet=line[:400]))
            if re.search(r"(?:sendRedirect|getWriter\(\)\.write|println)\s*\(", line) and _js_tainted(line, tainted):
                slug = "open_redirect" if "sendRedirect" in line else "xss"
                hits.append(RuleHit(slug, line_no, "Untrusted input reaches a response sink", 0.7, snippet=line[:400]))
        else:
            if re.search(r"createHash\(\s*['\"](md5|sha1)['\"]", line, re.I):
                hits.append(RuleHit("weak_cryptography", line_no, "Weak hash algorithm", 0.6, snippet=line[:400]))
            if "rejectUnauthorized" in line and "false" in line:
                hits.append(RuleHit("insecure_tls", line_no, "TLS verification disabled", 0.85, snippet=line[:400]))
            if "NODE_TLS_REJECT_UNAUTHORIZED" in line and "0" in line:
                hits.append(RuleHit("insecure_tls", line_no, "TLS verification disabled globally", 0.85, snippet=line[:400]))
            if re.search(r"algorithms\s*:\s*\[\s*['\"]none['\"]", line):
                hits.append(RuleHit("authentication_jwt", line_no, "JWT 'none' algorithm accepted", 0.92, snippet=line[:400]))
            if re.search(r"Object\.assign\s*\(|_\.merge\s*\(|_\.defaultsDeep\s*\(", line) and _js_tainted(line, tainted):
                hits.append(RuleHit("prototype_pollution", line_no, "Untrusted object merged into a target", 0.72, snippet=line[:400]))
            if re.search(r"Math\.random\(\)", line) and re.search(r"(?i)token|secret|otp|password|nonce|session", line):
                hits.append(RuleHit("insecure_randomness", line_no, "Non-cryptographic randomness for a security value", 0.65, snippet=line[:400]))
            if re.search(r"DEBUG\s*[:=]\s*true", line):
                hits.append(RuleHit("security_misconfiguration", line_no, "Debug mode enabled", 0.65, snippet=line[:400]))
    return hits


def _js_tainted(text: str, tainted: set[str]) -> bool:
    if _JS_TAINT_SOURCE.search(text):
        return True
    return any(re.search(rf"(?<![\w$.]){re.escape(name)}(?![\w$])", text) for name in tainted)


def _arg_after(text: str, keyword: str) -> str:
    index = text.find(keyword)
    if index < 0:
        return text
    return text[index + len(keyword):]


def _js_sinks(hits: list[RuleHit], line: str, line_no: int, tainted: set[str], language: str) -> None:
    def add(slug: str, reason: str, confidence: float = 0.75) -> None:
        hits.append(RuleHit(slug, line_no, reason, confidence, snippet=line[:400]))

    if re.search(r"(?:query|execute|raw|createQuery|prepareStatement|executeQuery|executeUpdate)\s*\(", line, re.I):
        static = re.sub(r"\$\{[^}]*\}", " ", line)
        if _SQL.search(static) and (
            "${" in line or re.search(r"[\"']\s*\+\s*", line) or ".concat(" in line
        ):
            add("sql_injection", "SQL query assembled with untrusted input", 0.82)

    if re.search(r"(?<![\w.])(?:eval|exec|execSync)\s*\(", line) and _js_tainted(line, tainted):
        add("command_injection", "Untrusted input reaches command or code execution", 0.88)
    if re.search(r"new\s+Function\s*\(", line) and _js_tainted(line, tainted):
        add("code_injection", "Untrusted input reaches new Function()", 0.85)
    if re.search(r"Runtime\.getRuntime\(\)\.exec\s*\(|ProcessBuilder\s*\(", line) and _js_tainted(line, tainted):
        add("command_injection", "Untrusted input reaches process execution", 0.88)
    if re.search(r"child_process\.(?:exec|execSync|spawn|spawnSync)\s*\(", line) and _js_tainted(line, tainted):
        add("command_injection", "Untrusted input reaches child_process", 0.85)

    if re.search(r"(?:innerHTML|outerHTML)\s*=", line) and _js_tainted(line, tainted):
        add("xss", "Untrusted input assigned to HTML sink", 0.85)
    if re.search(r"document\.write\s*\(|insertAdjacentHTML\s*\(|dangerouslySetInnerHTML", line) and _js_tainted(line, tainted):
        add("xss", "Untrusted input reaches a DOM HTML sink", 0.82)

    if re.search(r"(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlinkSync|unlink|sendFile)\s*\(", line):
        if _js_tainted(line, tainted):
            add("path_traversal_lfi_rfi", "Untrusted input reaches a filesystem operation", 0.78)
    if language == "java" and re.search(r"(?:FileInputStream|Files\.(?:read|write|delete|copy)|Paths\.get)\s*\(", line):
        if _js_tainted(line, tainted):
            add("path_traversal_lfi_rfi", "Untrusted input reaches a filesystem operation", 0.78)

    if re.search(r"(?<![\w.])(?:fetch|axios\.(?:get|post|put|delete|request)|http\.get|https\.get|request)\s*\(", line):
        if _js_tainted(line, tainted) and re.search(r"(?i)url|uri|host|endpoint|target|callback|https?://", line):
            add("ssrf", "Untrusted input controls an outbound request", 0.75)
    if re.search(r"new\s+URL\s*\(", line) and _js_tainted(line, tainted):
        add("ssrf", "Untrusted input constructs an outbound URL", 0.7)
    if re.search(r"HttpClient|URL\s*\(\s*\w+", line) and language == "java" and _js_tainted(line, tainted):
        add("ssrf", "Untrusted input constructs an outbound URL", 0.72)

    if re.search(r"(?:res\.redirect|response\.sendRedirect|redirect)\s*\(", line) and _js_tainted(line, tainted):
        add("open_redirect", "Untrusted input controls a redirect", 0.78)

    if re.search(r"unserialize\s*\(|readObject\s*\(|XMLDecoder", line) and _js_tainted(line, tainted):
        add("insecure_deserialization", "Untrusted data reaches a deserialization sink", 0.82)

    if re.search(r"(?<![\w.])(?:eval|exec|execSync)\s*\(", line) and _js_tainted(line, tainted):
        add("command_injection", "Untrusted input reaches eval/exec", 0.85)


def _dedupe(hits: Iterable[RuleHit]) -> list[RuleHit]:
    best: dict[tuple[str, int], RuleHit] = {}
    for hit in hits:
        key = (hit.slug, hit.line)
        current = best.get(key)
        if current is None or hit.confidence > current.confidence:
            if current and current.reason != hit.reason:
                hit.reason = f"{current.reason}; {hit.reason}"
            best[key] = hit
    return list(best.values())


def detect_unit(unit: CodeUnit) -> list[RuleHit]:
    if unit.language == "python":
        # The AST visitor covers the supported Python rules. Raw-text regex is
        # reserved for units that cannot be parsed, so vulnerable *samples*
        # embedded in strings are not reported as live findings.
        hits = _scan_python(unit) if unit.kind != "file" or _python_parses(unit.source) else _py_fallback(unit)
    else:
        hits = _scan_js_java(unit)
    return _dedupe(hits)


def _python_parses(source: str) -> bool:
    try:
        ast.parse(source)
        return True
    except SyntaxError:
        return False


def detect_project(files: dict[str, str]) -> list[RuleHit]:
    from ..parsing.parser import parse_file

    hits: list[RuleHit] = []
    for path, content in files.items():
        parsed = parse_file(path, content)
        for unit in parsed.units:
            for hit in detect_unit(unit):
                hit.snippet = hit.snippet or f"{path}:{hit.line}"
                hits.append(hit)
    return hits
