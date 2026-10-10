"""Extract function-level code units from source files.

Python uses the standard-library ``ast`` module (exact). JavaScript, TypeScript,
and Java use Tree-sitter when the ``tree-sitter-language-pack`` is installed,
and fall back to a tolerant brace/regex walker otherwise. Detection always
operates on :class:`CodeUnit` objects, so the parser backend is an
implementation detail.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Optional

from ..schemas import CodeUnit

_TS_LANG = {
    "javascript": "javascript",
    "typescript": "typescript",
    "java": "java",
}

_JS_FUNCTION_TYPES = {
    "function_declaration",
    "function_expression",
    "generator_function_declaration",
    "method_definition",
    "arrow_function",
}
_JAVA_FUNCTION_TYPES = {"method_declaration", "constructor_declaration"}


@dataclass
class ParseResult:
    units: list[CodeUnit] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Python
# --------------------------------------------------------------------------- #
def _python_imports(tree: ast.AST) -> list[str]:
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
    return [name for name in imports if name]


def parse_python(path: str, text: str) -> ParseResult:
    result = ParseResult()
    lines = text.splitlines()
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        result.errors.append(f"{path}: syntax error at line {exc.lineno}: {exc.msg}")
        return result

    result.imports = _python_imports(tree)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        start = node.lineno
        end = getattr(node, "end_lineno", node.lineno) or node.lineno
        source = "\n".join(lines[start - 1 : end])
        container = getattr(node, "parent_class", None)
        result.units.append(
            CodeUnit(
                path=path,
                language="python",
                name=node.name,
                container=container,
                start_line=start,
                end_line=end,
                source=source,
            )
        )
    # Attach class containers by scanning class bodies.
    containers = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    containers[(child.lineno, child.name)] = node.name
    for unit in result.units:
        key = (unit.start_line, unit.name)
        if key in containers:
            unit.container = containers[key]
    result.units.sort(key=lambda u: (u.start_line, u.name))
    return result


# --------------------------------------------------------------------------- #
# Tree-sitter (JS/TS/Java)
# --------------------------------------------------------------------------- #
def _get_ts_parser(language: str):
    try:
        from tree_sitter_language_pack import get_parser  # type: ignore
    except Exception:  # pragma: no cover - optional dependency
        return None
    try:
        return get_parser(_TS_LANG[language])
    except Exception:  # pragma: no cover
        return None


def _node_name(node, source: bytes) -> str:
    name_node = node.child_by_field_name("name")
    if name_node is not None:
        return source[name_node.start_byte : name_node.end_byte].decode("utf-8", "replace")
    parent = node.parent
    if parent is not None:
        parent_name = parent.child_by_field_name("name")
        if parent_name is not None:
            return source[parent_name.start_byte : parent_name.end_byte].decode("utf-8", "replace")
    return "<anonymous>"


def _walk_functions(node, source: bytes, language: str, out: list) -> None:
    kinds = _JAVA_FUNCTION_TYPES if language == "java" else _JS_FUNCTION_TYPES
    if node.type in kinds:
        start = node.start_point[0] + 1
        end = node.end_point[0] + 1
        text = source[node.start_byte : node.end_byte].decode("utf-8", "replace")
        out.append(
            CodeUnit(
                path="",
                language=language,
                name=_node_name(node, source),
                start_line=start,
                end_line=end,
                source=text,
            )
        )
        return  # do not descend into nested functions for the top-level unit
    for child in node.children:
        _walk_functions(child, source, language, out)


def parse_tree_sitter(path: str, text: str, language: str) -> Optional[ParseResult]:
    parser = _get_ts_parser(language)
    if parser is None:
        return None
    source = text.encode("utf-8")
    tree = parser.parse(source)
    units: list[CodeUnit] = []
    _walk_functions(tree.root_node, source, language, units)
    for unit in units:
        unit.path = path
    units.sort(key=lambda u: (u.start_line, u.name))
    if not units:
        # No function nodes (e.g. a script): fall back to a whole-file unit so
        # detection still runs on top-level statements.
        units = [_whole_file_unit(path, text, language)]
    return ParseResult(units=units)


# --------------------------------------------------------------------------- #
# Regex fallback
# --------------------------------------------------------------------------- #
_JS_FUNC_RE = re.compile(
    r"(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(|"
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>|"
    r"([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{",
)
_JAVA_METHOD_RE = re.compile(
    r"(?:public|private|protected|static|final|synchronized|abstract|\s)+"
    r"[\w<>\[\],.?]+\s+([A-Za-z_$][\w$]*)\s*\([^;{]*\)\s*(?:throws\s+[\w,.\s]+)?\{",
)


def _brace_block(lines: list[str], start: int) -> int:
    """Return the 1-based end line of a brace-delimited block from ``start``."""
    depth = 0
    started = False
    for i in range(start - 1, len(lines)):
        for ch in lines[i]:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
        if started and depth <= 0:
            return i + 1
    return len(lines)


def parse_regex(path: str, text: str, language: str) -> ParseResult:
    lines = text.splitlines()
    pattern = _JAVA_METHOD_RE if language == "java" else _JS_FUNC_RE
    units: list[CodeUnit] = []
    for i, line in enumerate(lines):
        match = pattern.search(line)
        if not match:
            continue
        name = next((g for g in match.groups() if g), "<anonymous>")
        start = i + 1
        end = _brace_block(lines, start)
        units.append(
            CodeUnit(
                path=path,
                language=language,
                name=name,
                start_line=start,
                end_line=end,
                source="\n".join(lines[start - 1 : end]),
            )
        )
    if not units:
        units = [_whole_file_unit(path, text, language)]
    return ParseResult(units=units)


def _whole_file_unit(path: str, text: str, language: str) -> CodeUnit:
    lines = text.splitlines()
    return CodeUnit(
        path=path,
        language=language,
        name="<module>",
        start_line=1,
        end_line=max(1, len(lines)),
        source=text,
    )


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def parse_file(path: str, text: str, language: Optional[str] = None) -> ParseResult:
    language = language or _guess_language(path)
    if language == "python":
        return parse_python(path, text)
    ts_result = parse_tree_sitter(path, text, language)
    if ts_result is not None:
        return ts_result
    return parse_regex(path, text, language)


def _guess_language(path: str) -> str:
    from ..ingestion.loader import detect_language

    return detect_language(path) or "text"


def approx_tokens(text: str) -> int:
    """Cheap token estimate (~4 chars/token) for chunk sizing."""
    return max(1, len(text) // 4)


def chunk_source(source: str, max_tokens: int = 512, overlap_lines: int = 5):
    """AST-aware-ish sliding window over lines for the model's token limit.

    Yields ``(start_line_offset, text)`` where offset is 0-based within source.
    """
    lines = source.splitlines() or [""]
    if approx_tokens(source) <= max_tokens:
        yield 0, source
        return
    window: list[str] = []
    window_tokens = 0
    start = 0
    for idx, line in enumerate(lines):
        line_tokens = approx_tokens(line) + 1
        if window and window_tokens + line_tokens > max_tokens:
            yield start, "\n".join(window)
            keep = window[-overlap_lines:] if overlap_lines else []
            start = idx - len(keep)
            window = list(keep)
            window_tokens = sum(approx_tokens(l) + 1 for l in window)
        window.append(line)
        window_tokens += line_tokens
    if window:
        yield start, "\n".join(window)
