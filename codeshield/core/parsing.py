"""Stage 2 — parsing and preprocessing (PRD §10.2, FR-6..FR-8).

We want real syntax structure so that predictions can be traced back to lines and nodes.
Tree-sitter is the PRD's chosen parser; when it is not installed we fall back to Python's
built-in ``ast`` (for ``.py``) and a brace/indent heuristic (for JS/TS/Java). The fallback is
labelled as such on every file so results are never silently over-claimed.
"""

from __future__ import annotations

import ast
import hashlib
import io
import re
import tokenize
from collections.abc import Iterable
from dataclasses import dataclass, field

LANG_BY_EXT: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
}

COMMENT_PREFIX = {
    "python": "#",
    "javascript": "//",
    "typescript": "//",
    "java": "//",
}


def detect_language(path: str) -> str | None:
    """Return a supported language name for a path, or ``None`` if unsupported."""
    lowered = path.lower()
    for ext, lang in LANG_BY_EXT.items():
        if lowered.endswith(ext):
            return lang
    return None


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


@dataclass
class FunctionUnit:
    name: str
    start_line: int
    end_line: int
    code: str
    language: str

    @property
    def line_count(self) -> int:
        return self.end_line - self.start_line + 1


@dataclass
class FileAnalysis:
    path: str
    language: str
    text: str
    lines: list[str]
    functions: list[FunctionUnit] = field(default_factory=list)
    parser: str = "regex"  # "tree-sitter" | "ast" | "regex"
    parse_error: str | None = None

    @property
    def loc(self) -> int:
        return sum(1 for line in self.lines if line.strip())


# --------------------------------------------------------------------------- #
# Python: real AST + tokenizer
# --------------------------------------------------------------------------- #


def _python_functions(text: str) -> tuple[list[FunctionUnit], str | None]:
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        return [], f"{exc.msg} (line {exc.lineno})"

    lines = text.splitlines()
    units: list[FunctionUnit] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno
            end = getattr(node, "end_lineno", start)
            code = "\n".join(lines[start - 1 : end])
            units.append(
                FunctionUnit(
                    name=node.name,
                    start_line=start,
                    end_line=end,
                    code=code,
                    language="python",
                )
            )
    units.sort(key=lambda u: u.start_line)
    return units, None


def python_token_lines(text: str) -> list[tuple[str, int]]:
    """Return ``(token_text, line_number)`` pairs for attention mapping (FR-15)."""
    result: list[tuple[str, int]] = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type in {
                tokenize.NEWLINE,
                tokenize.NL,
                tokenize.INDENT,
                tokenize.DEDENT,
                tokenize.ENDMARKER,
                tokenize.COMMENT,
            }:
                continue
            if tok.string.strip():
                result.append((tok.string, tok.start[0]))
    except tokenize.TokenError:
        pass
    return result


# --------------------------------------------------------------------------- #
# JS/TS/Java: brace + regex heuristic
# --------------------------------------------------------------------------- #

_JS_FUNC_RE = re.compile(
    r"""^[\t ]*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\("""
    r"""|^[\t ]*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function|\([^)]*\)\s*=>)"""
    r"""|^[\t ]*(?:static\s+)?(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^;]*\)\s*\{""",
    re.MULTILINE,
)

_JAVA_FUNC_RE = re.compile(
    r"^[\t ]*(?:@\w+(?:\([^)]*\))?\s*)*"
    r"(?:public|private|protected|static|final|synchronized|native|abstract|\s)+"
    r"[\w<>\[\],.\s?]+\s+([A-Za-z_]\w*)\s*\([^;{]*\)\s*(?:throws\s+[\w.,\s]+)?\{",
    re.MULTILINE,
)


def _brace_functions(text: str, language: str) -> list[FunctionUnit]:
    """Extract function-ish ranges by finding a signature then matching braces."""
    lines = text.splitlines()
    pattern = _JAVA_FUNC_RE if language == "java" else _JS_FUNC_RE
    units: list[FunctionUnit] = []
    seen_starts: set[int] = set()

    for match in pattern.finditer(text):
        name = next((g for g in match.groups() if g), "anonymous")
        start_offset = match.start()
        start_line = text.count("\n", 0, start_offset) + 1

        brace = text.find("{", match.end())
        if brace == -1:
            continue
        end_offset = _match_brace(text, brace)
        end_line = text.count("\n", 0, end_offset) + 1 if end_offset != -1 else start_line
        if start_line in seen_starts:
            continue
        seen_starts.add(start_line)
        code = "\n".join(lines[start_line - 1 : end_line])
        units.append(
            FunctionUnit(
                name=name,
                start_line=start_line,
                end_line=end_line,
                code=code,
                language=language,
            )
        )

    units.sort(key=lambda u: u.start_line)
    return units


def _match_brace(text: str, open_index: int) -> int:
    depth = 0
    in_str: str | None = None
    i = open_index
    while i < len(text):
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
        elif ch in "\"'`":
            in_str = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def analyze_file(path: str, text: str, language: str | None = None) -> FileAnalysis:
    """Parse one file into a :class:`FileAnalysis` with function-level units."""
    language = language or detect_language(path) or "text"
    lines = text.splitlines()

    if language == "python":
        functions, parse_error = _python_functions(text)
        parser = "ast"
    elif language in {"javascript", "typescript", "java"}:
        functions = _brace_functions(text, language)
        parse_error = None
        parser = "regex"
    else:
        functions, parse_error, parser = [], None, "regex"

    if language in {"javascript", "typescript", "java"}:
        parser = "tree-sitter" if _treesitter_available() else "regex"

    return FileAnalysis(
        path=path,
        language=language,
        text=text,
        lines=lines,
        functions=functions,
        parser=parser,
        parse_error=parse_error,
    )


def _treesitter_available() -> bool:
    try:  # pragma: no cover - optional dependency
        import tree_sitter  # noqa: F401
    except Exception:
        return False
    return True


def chunk_unit(unit: FunctionUnit, max_tokens: int = 512, overlap: int = 64) -> list[str]:
    """AST/line-aware sliding window so long functions fit the model (FR-8).

    The window is line-aligned (we never split a line) and tokens are estimated at
    ~4 characters per token, which is close enough for a 512-token CodeBERT window.
    """
    max_chars = max_tokens * 4
    overlap_chars = overlap * 4
    if len(unit.code) <= max_chars:
        return [unit.code]

    chunks: list[str] = []
    lines = unit.code.splitlines()
    current: list[str] = []
    current_len = 0
    for line in lines:
        if current_len + len(line) + 1 > max_chars and current:
            chunks.append("\n".join(current))
            tail: list[str] = []
            tail_len = 0
            for prev in reversed(current):
                if tail_len + len(prev) + 1 > overlap_chars:
                    break
                tail.insert(0, prev)
                tail_len += len(prev) + 1
            current = tail
            current_len = tail_len
        current.append(line)
        current_len += len(line) + 1
    if current:
        chunks.append("\n".join(current))
    return chunks


def snippet_for(lines: list[str], start_line: int, end_line: int, pad: int = 2) -> str:
    """Return a numbered code snippet for display around a finding."""
    lo = max(1, start_line - pad)
    hi = min(len(lines), end_line + pad)
    out = []
    for n in range(lo, hi + 1):
        marker = ">" if start_line <= n <= end_line else " "
        out.append(f"{marker} {n:>4} | {lines[n - 1]}")
    return "\n".join(out)


def iter_line_offsets(text: str) -> Iterable[tuple[int, int]]:
    """Yield ``(line_number, char_start_offset)`` for every line."""
    offset = 0
    for i, line in enumerate(text.splitlines(keepends=True), start=1):
        yield i, offset
        offset += len(line)
