#!/usr/bin/env python
"""Command-line scanner.

Examples
--------
    python scripts/run_scan.py ../samples/vulnerable
    python scripts/run_scan.py --repo https://github.com/org/app --branch main
    python scripts/run_scan.py --code-file app.py --format sarif --out report.sarif

Exit codes: 0 = no findings, 2 = findings at/above --fail-on, 1 = error.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running directly from the backend directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from codeshield import config  # noqa: E402
from codeshield.ingestion.loader import IngestionError  # noqa: E402
from codeshield.pipeline import CodeShieldPipeline  # noqa: E402
from codeshield.reporting import reporter  # noqa: E402
from codeshield.schemas import Scan  # noqa: E402

_SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _render(scan: Scan, fmt: str) -> str | bytes:
    if fmt == "json":
        return reporter.to_json(scan)
    if fmt == "sarif":
        import json

        return json.dumps(reporter.to_sarif(scan), indent=2)
    if fmt == "html":
        return reporter.to_html(scan)
    if fmt == "pdf":
        return reporter.to_pdf(scan)
    raise ValueError(f"unknown format: {fmt}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan code for vulnerabilities with CodeShield AI.")
    parser.add_argument("path", nargs="?", help="File or directory to scan")
    parser.add_argument("--repo", help="Git repository URL to scan")
    parser.add_argument("--branch", help="Branch to clone when using --repo")
    parser.add_argument("--code-file", help="A single source file to scan (alias of path)")
    parser.add_argument("--format", default="text", choices=["text", "json", "sarif", "html", "pdf"])
    parser.add_argument("--out", help="Write the report to this path")
    parser.add_argument("--no-patches", action="store_true", help="Skip patch generation")
    parser.add_argument("--fail-on", default="high", choices=list(_SEV), help="Exit 2 if a finding is at/above this severity")
    args = parser.parse_args(argv)

    pipeline = CodeShieldPipeline()
    try:
        if args.repo:
            scan = pipeline.scan_repo(args.repo, args.branch, generate_patches=not args.no_patches)
        else:
            target = args.code_file or args.path
            if not target:
                parser.error("provide a path, --code-file, or --repo")
            root = Path(target)
            if root.is_file():
                scan = pipeline.scan_files(
                    pipeline_files(root), target=str(root), generate_patches=not args.no_patches
                )
            else:
                scan = pipeline.scan_paths(root, generate_patches=not args.no_patches)
    except IngestionError as exc:
        print(f"ingestion error: {exc}", file=sys.stderr)
        return 1

    if args.format == "text":
        _print_text(scan)
    else:
        payload = _render(scan, args.format)
        if args.out:
            Path(args.out).write_bytes(payload if isinstance(payload, bytes) else payload.encode("utf-8"))
            print(f"wrote {args.out}")
        elif isinstance(payload, bytes):
            sys.stdout.buffer.write(payload)
        else:
            print(payload)

    threshold = _SEV[args.fail_on]
    worst = max((_SEV.get(f.severity, 0) for f in scan.findings), default=0)
    return 2 if worst >= threshold else 0


def pipeline_files(path: Path):
    from codeshield.ingestion.loader import SourceFile, detect_language

    language = detect_language(path.name)
    if not language:
        raise IngestionError(f"unsupported file type: {path.name}")
    text = path.read_text(encoding="utf-8", errors="replace")
    return [SourceFile(path=path.name, language=language, text=text, size=len(text))]


def _print_text(scan: Scan) -> None:
    print(f"CodeShield AI scan {scan.id} — {scan.target}")
    print(f"files={scan.summary.files_scanned} units={scan.summary.units_scanned} "
          f"findings={scan.summary.total_findings} model={'yes' if scan.summary.model_used else 'no'}")
    print(f"by severity: {scan.summary.by_severity}")
    print("-" * 78)
    for f in sorted(scan.findings, key=lambda x: -_SEV.get(x.severity, 0)):
        print(f"[{f.severity.upper():8s}] {f.cwe} {f.path}:{f.start_line} ({f.function}) "
              f"engine={f.engine} conf={f.confidence:.0%}")
        print(f"           {f.message}")
        for c in f.patch_candidates[:1]:
            print(f"           patch[{c.verification}] {c.summary}")
    if not scan.findings:
        print("No findings.")


if __name__ == "__main__":
    raise SystemExit(main())
