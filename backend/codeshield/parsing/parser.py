"""Language-aware unit extraction for Python, JavaScript/TypeScript, and Java."""
from __future__ import annotations

import ast
import re
import textwrap
from dataclasses import dataclass, field
from typing import Optional

from ..schemas import CodeUnit

try:
    from tree_sitter_language_pack import get_parser as _get_parser
except Exception:
    _get_parser = None

_FUNC_TYPES = {
    "javascript": {
        "function_declaration", "function", "function_expression", "generator_function",
        "generator_function_declaration", "arrow_function", "method_definition",
    },
    "typescript": {
        "function_declaration", "function", "function_expression", "generator_function",
        "generator_function_declaration", "arrow_function", "method_definition",
        "method_signature",
    },
    "tsx": {
        "function_declaration", "function", "function_expression", "generator_function",
        "generator_function_declaration", "arrow_function", "method_definition",
    },
    "java": {
        "method_declaration", "constructor_declaration", "compact_constructor_declaration",
    },
}
_JS_LANGS = {"javascript", "typescript", "tsx"}


@dataclass
class ParsedFile:
    path: str
    language: str
    units: list[CodeUnit] = field(default_factory=list)
    error: Optional[str] = None
    total_lines: int = 0


def detect_language(path: str) -> str:
    suffix = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    return {
        "py": "python", "js": "javascript", "jsx": "javascript", "mjs": "javascript",
        "cjs": "javascript", "ts": "typescript", "tsx": "tsx", "java": "java",
    }.get(suffix, "unknown")


def parse_file(path: str, content: str) -> ParsedFile:
    language = detect_language(path)
    lines = content.splitlines()
    if language == "python":
        return _parse_python(path, content, len(lines))
    if language in _JS_LANGS or language == "java":
        return _parse_treesitter(path, content, language, len(lines))
    return ParsedFile(path=path, language=language, total_lines=len(lines), error="Unsupported language")


def _slice(lines: list[str], start: int, end: int) -> str:
    return textwrap.dedent("\n".join(lines[start - 1:end]))


def _module_chunks(lines: list[str], ranges: list[tuple[int, int]], path: str, language: str) -> list[CodeUnit]:
    covered = [False] * (len(lines) + 2)
    for start, end in ranges:
        for line in range(max(1, start), min(len(lines), end) + 1):
            covered[line] = True
    chunks: list[CodeUnit] = []
    cursor = 1
    while cursor <= len(lines):
        if covered[cursor]:
            cursor += 1
            continue
        start = cursor
        while cursor <= len(lines) and not covered[cursor]:
            cursor += 1
        end = cursor - 1
        body = lines[start - 1:end]
        meaningful = [line for line in body if line.strip() and not line.strip().startswith(("#", "//", "/*", "*"))]
        if meaningful:
            chunks.append(
                CodeUnit(
                    path=path, language=language, name="<module>", start_line=start,
                    end_line=end, source=_slice(lines, start, end), kind="module",
                )
            )
    return chunks


def _parse_python(path: str, source: str, total_lines: int) -> ParsedFile:
    lines = source.splitlines()
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        unit = CodeUnit(
            path=path, language="python", name="<file>", start_line=1,
            end_line=max(1, total_lines), source=source, kind="file",
        )
        return ParsedFile(
            path=path, language="python", units=[unit], total_lines=total_lines,
            error=f"Python parse error at line {exc.lineno}: {exc.msg}",
        )
    units: list[CodeUnit] = []
    ranges: list[tuple[int, int]] = []

    def visit(node: ast.AST, container: Optional[str] = None) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = min([child.lineno] + [d.lineno for d in child.decorator_list])
                end = getattr(child, "end_lineno", child.lineno)
                name = f"{container}.{child.name}" if container else child.name
                signature = _python_signature(child)
                ranges.append((start, end))
                units.append(
                    CodeUnit(
                        path=path, language="python", name=name, start_line=start,
                        end_line=end, source=_slice(lines, start, end),
                        container=container, signature=signature, kind="function",
                    )
                )
                visit(child, name)
            elif isinstance(child, ast.ClassDef):
                name = f"{container}.{child.name}" if container else child.name
                visit(child, name)
            else:
                visit(child, container)

    visit(tree)
    units.sort(key=lambda u: (u.start_line, u.end_line))
    units.extend(_module_chunks(lines, ranges, path, "python"))
    if not units:
        units.append(
            CodeUnit(
                path=path, language="python", name="<module>", start_line=1,
                end_line=max(1, total_lines), source=source, kind="file",
            )
        )
    units.sort(key=lambda u: (u.start_line, u.end_line))
    return ParsedFile(path=path, language="python", units=units, total_lines=total_lines)


def _python_signature(node: ast.AST) -> str:
    try:
        args = ast.unparse(node.args) if hasattr(ast, "unparse") else ""
    except Exception:
        args = ""
    prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    return f"{prefix} {node.name}({args})"


def _node_text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _node_name(node, source_bytes: bytes) -> str:
    for field_name in ("name", "property"):
        child = node.child_by_field_name(field_name)
        if child is not None:
            return _node_text(child, source_bytes)
    parent = node.parent
    if parent is not None and parent.type == "variable_declarator":
        name = parent.child_by_field_name("name")
        if name is not None:
            return _node_text(name, source_bytes)
    if parent is not None and parent.type == "assignment":
        left = parent.child_by_field_name("left")
        if left is not None:
            return _node_text(left, source_bytes)[:80]
    if parent is not None and parent.type == "pair":
        key = parent.child_by_field_name("key")
        if key is not None:
            return _node_text(key, source_bytes)[:80]
    return "<anonymous>"


def _parse_treesitter(path: str, source: str, language: str, total_lines: int) -> ParsedFile:
    if _get_parser is None:
        return _fallback_regex(path, source, language, total_lines)
    parser_name = "tsx" if language == "tsx" else language
    try:
        parser = _get_parser(parser_name)
    except Exception:
        return _fallback_regex(path, source, language, total_lines)
    source_bytes = source.encode("utf-8")
    try:
        tree = parser.parse(source_bytes)
    except Exception as exc:
        return ParsedFile(
            path=path, language=language, total_lines=total_lines,
            error=f"Parser failure: {exc}",
        )
    wanted = _FUNC_TYPES.get(language, set())
    lines = source.splitlines()
    units: list[CodeUnit] = []
    ranges: list[tuple[int, int]] = []

    def visit(node, container: Optional[str] = None) -> None:
        if node.type in wanted:
            name = _node_name(node, source_bytes)
            if container and node.parent is not None and node.parent.type in {
                "class_declaration", "class_body", "class_definition", "program",
            }:
                name = f"{container}.{name}" if node.parent.type != "program" else name
            start = node.start_point[0] + 1
            end = node.end_point[0] + 1
            declarations = ("function_declaration", "method_definition", "method_declaration",
                            "constructor_declaration", "generator_function_declaration")
            if node.type == "arrow_function" and node.parent is not None:
                parent_start = node.parent.start_point[0] + 1
                if parent_start < start:
                    start = parent_start
            if node.type in declarations or node.type in {
                "function_expression", "function", "arrow_function",
            }:
                ranges.append((start, end))
            units.append(
                CodeUnit(
                    path=path, language=language, name=name, start_line=start, end_line=end,
                    source=_slice(lines, start, end), container=container,
                    signature=_signature_line(lines, start), kind="function",
                )
            )
            visit_children(node, container, skip_self=True)
        elif node.type in {"class_declaration", "class_definition", "class_body"}:
            class_name = container
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                class_name = _node_text(name_node, source_bytes)
            visit_children(node, class_name)
        else:
            visit_children(node, container)

    def visit_children(node, container, skip_self=False):
        for child in node.children:
            visit(child, container)

    visit(tree.root_node)
    ranges.sort()
    units.sort(key=lambda u: (u.start_line, u.end_line))
    if language != "java":
        units.extend(_module_chunks(lines, ranges, path, language))
    if not units:
        units.append(
            CodeUnit(
                path=path, language=language, name="<file>", start_line=1,
                end_line=max(1, total_lines), source=source, kind="file",
            )
        )
    units.sort(key=lambda u: (u.start_line, u.end_line))
    return ParsedFile(path=path, language=language, units=units, total_lines=total_lines)


def _signature_line(lines: list[str], start: int) -> str:
    for line in lines[start - 1:start + 4]:
        if "(" in line:
            return line.strip()[:300]
    return lines[start - 1].strip()[:300] if 1 <= start <= len(lines) else ""


_JS_FUNCTION = re.compile(
    r"^\s*(?:export\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\("
)
_JS_ARROW = re.compile(
    r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?"
    r"(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>"
)
_JS_METHOD = re.compile(r"^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{")
_RESERVED = {
    "if", "for", "while", "switch", "catch", "function", "with", "return",
    "else", "do", "try", "finally", "throw", "new", "typeof", "delete",
    "void", "await", "yield", "constructor", "super", "this",
}
_JAVA_METHOD = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final|abstract|synchronized|native|default)\s+)*"
    r"[\w<>\[\],.?]+\s+([A-Za-z_$][\w$]*)\s*\([^;]*\)\s*(?:throws\s+[\w., ]+)?\{"
)


def _fallback_regex(path: str, source: str, language: str, total_lines: int) -> ParsedFile:
    lines = source.splitlines()
    units: list[CodeUnit] = []
    ranges: list[tuple[int, int]] = []
    patterns = [_JS_FUNCTION, _JS_ARROW, _JS_METHOD] if language in _JS_LANGS else [_JAVA_METHOD]
    for index, line in enumerate(lines):
        match = None
        for pattern in patterns:
            match = pattern.match(line)
            if match:
                break
        if not match:
            continue
        start = index + 1
        end = _brace_end(lines, index)
        name = match.group(1)
        if name in _RESERVED:
            continue
        ranges.append((start, end))
        units.append(
            CodeUnit(
                path=path, language=language, name=name, start_line=start, end_line=end,
                source=_slice(lines, start, end), signature=line.strip()[:300],
            )
        )
    if language != "java":
        units.extend(_module_chunks(lines, ranges, path, language))
    if not units:
        units.append(
            CodeUnit(
                path=path, language=language, name="<file>", start_line=1,
                end_line=max(1, total_lines), source=source, kind="file",
            )
        )
    units.sort(key=lambda u: (u.start_line, u.end_line))
    return ParsedFile(path=path, language=language, units=units, total_lines=total_lines)


def _brace_end(lines: list[str], start_index: int) -> int:
    depth = 0
    started = False
    for index in range(start_index, min(len(lines), start_index + 1200)):
        line = _strip_strings(lines[index])
        for char in line:
            if char == "{":
                depth += 1
                started = True
            elif char == "}":
                depth -= 1
                if started and depth <= 0:
                    return index + 1
    return min(len(lines), start_index + 200)


def _strip_strings(line: str) -> str:
    return re.sub(r"(['\"]).*?\1", "", line)


def chunk_source(source: str, max_lines: int = 120, overlap: int = 20) -> list[str]:
    lines = source.splitlines()
    if len(lines) <= max_lines:
        return [source]
    chunks = []
    step = max(1, max_lines - overlap)
    for start in range(0, len(lines), step):
        end = min(len(lines), start + max_lines)
        chunks.append("\n".join(lines[start:end]))
        if end >= len(lines):
            break
    return chunks
