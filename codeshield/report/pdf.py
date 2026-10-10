"""A small, dependency-free PDF report writer (PRD §7.6 FR-29, §12).

Generating a PDF with no third-party library keeps the MVP installable on a student laptop.
The output is a plain, paginated, text report: an executive summary followed by per-finding
sections with the code snippet, rationale and the best (verified) patch.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..models import PatchStatus, ScanResult

PAGE_WIDTH = 612
PAGE_HEIGHT = 792
MARGIN = 40
BODY_SIZE = 9
LEADING = 12
LINES_PER_PAGE = int((PAGE_HEIGHT - 2 * MARGIN) / LEADING)


@dataclass
class _Line:
    text: str
    bold: bool = False
    size: int = BODY_SIZE


def _escape(text: str) -> str:
    # PDF text is in Latin-1; normalise and escape the string delimiters.
    safe = text.encode("latin-1", errors="replace").decode("latin-1")
    return safe.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def _wrap(text: str, width: int) -> list[str]:
    text = text.replace("\t", "    ")
    if len(text) <= width:
        return [text]
    words = text.split(" ")
    lines: list[str] = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines


def _content_stream(lines: list[_Line]) -> bytes:
    out = ["BT", f"{BODY_SIZE} TL", f"{MARGIN} {PAGE_HEIGHT - MARGIN} Td"]
    current_font = "F1"
    current_size = BODY_SIZE
    first = True
    for line in lines:
        font = "F2" if line.bold else "F1"
        size = line.size
        if first:
            out.append(f"/{font} {size} Tf")
            current_font, current_size = font, size
            first = False
        elif font != current_font or size != current_size:
            out.append(f"/{font} {size} Tf")
            current_font, current_size = font, size
        out.append(f"({_escape(line.text)}) Tj")
        out.append("T*")
    out.append("ET")
    return "\n".join(out).encode("latin-1", errors="replace")


def _build_pdf(pages: list[list[_Line]]) -> bytes:
    objects: list[bytes] = []

    def add(obj: bytes) -> int:
        objects.append(obj)
        return len(objects)

    catalog_num = 1
    pages_num = 2
    font_regular_num = 3
    font_bold_num = 4

    # Reserve catalog + pages dict + two fonts, then page/content pairs.
    first_page = 5
    kids: list[int] = []
    page_objs: list[tuple[int, int, list[_Line]]] = []
    for i, page_lines in enumerate(pages):
        page_num = first_page + i * 2
        content_num = page_num + 1
        kids.append(page_num)
        page_objs.append((page_num, content_num, page_lines))

    # Normalise object order: we fill placeholders by index.
    objects = [b""] * (first_page - 1 + len(pages) * 2)

    def set_obj(num: int, obj: bytes) -> None:
        objects[num - 1] = obj

    set_obj(catalog_num, f"<< /Type /Catalog /Pages {pages_num} 0 R >>".encode())
    kids_ref = " ".join(f"{k} 0 R" for k in kids)
    set_obj(
        pages_num,
        f"<< /Type /Pages /Kids [{kids_ref}] /Count {len(kids)} >>".encode(),
    )
    set_obj(
        font_regular_num,
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
    )
    set_obj(
        font_bold_num,
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
    )

    for page_num, content_num, page_lines in page_objs:
        set_obj(
            page_num,
            (
                f"<< /Type /Page /Parent {pages_num} 0 R "
                f"/MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
                f"/Resources << /Font << /F1 {font_regular_num} 0 R /F2 {font_bold_num} 0 R >> >> "
                f"/Contents {content_num} 0 R >>"
            ).encode(),
        )
        stream = _content_stream(page_lines)
        set_obj(
            content_num,
            b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
        )

    # Serialise with an xref table.
    buffer = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: list[int] = []
    for num, obj in enumerate(objects, start=1):
        offsets.append(len(buffer))
        buffer += f"{num} 0 obj\n".encode() + obj + b"\nendobj\n"

    xref_offset = len(buffer)
    buffer += f"xref\n0 {len(objects) + 1}\n".encode()
    buffer += b"0000000000 65535 f \n"
    for offset in offsets:
        buffer += f"{offset:010d} 00000 n \n".encode()
    buffer += (
        f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_num} 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n"
    ).encode()
    return bytes(buffer)


# --------------------------------------------------------------------------- #
# Report content
# --------------------------------------------------------------------------- #

_STATUS_LABEL = {
    PatchStatus.verified: "VERIFIED",
    PatchStatus.partial: "PARTIALLY VERIFIED",
    PatchStatus.unverified: "UNVERIFIED — do not treat as safe",
}


def _scan_lines(scan: ScanResult) -> list[_Line]:
    lines: list[_Line] = []
    lines.append(_Line("CodeShield AI — Security Report", bold=True, size=16))
    lines.append(_Line(f"Scan {scan.id}   source: {scan.source}", size=9))
    lines.append(_Line(f"Generated: {scan.finished_at or scan.created_at}", size=9))
    if scan.model_version:
        lines.append(_Line(f"Detection model: {scan.model_version}", size=9))
    else:
        lines.append(_Line("Detection model: rule-based baseline only", size=9))
    lines.append(_Line("", size=9))

    lines.append(_Line("Executive summary", bold=True, size=12))
    summary = scan.summary
    lines.append(_Line(f"Files scanned: {summary.files_scanned}  skipped: {summary.files_skipped}"))
    lines.append(_Line(f"Total findings: {summary.total_findings}"))
    for severity, count in summary.by_severity.items():
        if count:
            lines.append(_Line(f"  {severity.upper():<9} {count}"))
    if summary.by_cwe:
        top = ", ".join(f"{cwe}={n}" for cwe, n in list(summary.by_cwe.items())[:8])
        lines.append(_Line(f"CWEs: {top}"))
    lines.append(
        _Line(f"Patches verified: {summary.patches_verified} of {len(scan.patches)} generated")
    )
    if scan.engine_notes:
        lines.append(_Line("Engine notes:", bold=True))
        for note in scan.engine_notes[:6]:
            for wrapped in _wrap(f"- {note}", 100):
                lines.append(_Line(wrapped, size=8))
    lines.append(_Line("", size=9))

    lines.append(_Line("Findings", bold=True, size=12))
    if not scan.findings:
        lines.append(_Line("No findings. (Absence of findings is not a guarantee of security.)"))
        return lines

    patches_by_finding = {p.finding_id: p for p in scan.patches}
    for finding in scan.findings:
        lines.append(
            _Line(
                f"[{finding.severity.value.upper()}] {finding.cwe} {finding.cwe_name}",
                bold=True,
                size=11,
            )
        )
        lines.append(
            _Line(
                f"{finding.file}:{finding.location.start_line}"
                + (f"  in {finding.location.function}()" if finding.location.function else "")
            )
        )
        lines.append(_Line(f"Confidence: {finding.confidence:.0%}   engine: {finding.engine.value}"))
        for wrapped in _wrap(f"Rationale: {finding.rationale}", 100):
            lines.append(_Line(wrapped))
        if finding.remediation:
            for wrapped in _wrap(f"Remediation: {finding.remediation}", 100):
                lines.append(_Line(wrapped))
        if finding.snippet:
            lines.append(_Line("Code:", bold=True))
            for snippet_line in finding.snippet.splitlines()[:20]:
                lines.append(_Line(snippet_line, size=8))

        patch = patches_by_finding.get(finding.id)
        if patch:
            lines.append(_Line(f"Patch ({_STATUS_LABEL[patch.status]}): {patch.summary}", bold=True))
            for check in patch.verification:
                lines.append(_Line(f"  check: {check}", size=8))
            for diff_line in patch.diff.splitlines()[:24]:
                lines.append(_Line(diff_line, size=8))
        else:
            lines.append(_Line("Patch: none generated.", size=8))
        lines.append(_Line("", size=9))

    lines.append(_Line("", size=9))
    lines.append(
        _Line(
            "Findings are decision support, not a security certification. "
            "Unverified patches must be reviewed before use.",
            size=8,
        )
    )
    return lines


def _paginate(lines: list[_Line]) -> list[list[_Line]]:
    pages: list[list[_Line]] = []
    for index in range(0, len(lines), LINES_PER_PAGE):
        pages.append(lines[index : index + LINES_PER_PAGE])
    return pages or [[_Line("CodeShield AI")]]


def to_pdf(scan: ScanResult) -> bytes:
    """Render a scan result to PDF bytes."""
    return _build_pdf(_paginate(_scan_lines(scan)))


def write_pdf(scan: ScanResult, path: str) -> str:
    data = to_pdf(scan)
    with open(path, "wb") as handle:
        handle.write(data)
    return path
