#!/usr/bin/env python
"""Command-line scanner.

Examples
--------
    python scripts/run_scan.py ../samples/vulnerable
    python scripts/run_scan.py --repo https://github.com/org/app --branch main
    python scripts/run_scan.py --code-file app.py --format sarif --out report.sarif

Exit codes: 0 = no findings at/above the gate, 2 = findings at/above the gate,
1 = error.
"""
from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path

# Allow running directly from the backend directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from codeshield import config  # noqa: E402
from codeshield.ingestion.loader import IngestionError, language_for  # noqa: E402
from codeshield.pipeline import run_scan  # noqa: E402
from codeshield.reporting import reporter  # noqa: E402
from codeshield.schemas import Scan  # noqa: E402

_SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _render(scan: Scan, fmt: str) -> str | bytes:
    if fmt == "json":
        return reporter.build_json(scan)
    if fmt == "sarif":
        import json

        return json.dumps(reporter.build_sarif(scan), indent=2)
    if fmt == "html":
        return reporter.build_html(scan)
    if fmt == "pdf":
        return reporter.build_pdf(scan)
    raise ValueError(f"unknown format: {fmt}")


def collect_path(target: Path) -> dict:
    """Build an upload source from a local file or directory."""
    if target.is_file():
        if not language_for(target.name):
            raise IngestionError(f"unsupported file type: {target.name}")
        return {
            "type": "upload",
            "files": [(target.name, target.read_bytes())],
        }
    if not target.is_dir():
        raise IngestionError(f"path not found: {target}")

    files: list[tuple[str, bytes]] = []
    total = 0
    for path in sorted(target.rglob("*")):
        if not path.is_file() or not language_for(path.name):
            continue
        relative = path.relative_to(target).as_posix()
        if any(part in config.SKIP_DIRS for part in Path(relative).parts):
            continue
        data = path.read_bytes()
        if len(data) > config.MAX_FILE_BYTES:
            continue
        total += len(data)
        if len(files) >= config.MAX_FILES or total > config.MAX_TOTAL_BYTES:
            raise IngestionError("path exceeds the configured scan size limits")
        files.append((relative, data))
    if not files:
        raise IngestionError("no supported source files were found")
    return {"type": "upload", "files": files}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan code for vulnerabilities with CodeShield AI.")
    parser.add_argument("path", nargs="?", help="File or directory to scan")
    parser.add_argument("--repo", help="Git repository URL to scan")
    parser.add_argument("--branch", help="Branch to clone when using --repo")
    parser.add_argument("--commit", help="Commit SHA to check out when using --repo")
    parser.add_argument("--code-file", help="A single source file to scan (alias of path)")
    parser.add_argument("--format", default="text", choices=["text", "json", "sarif", "html", "pdf"])
    parser.add_argument("--out", help="Write the report to this path")
    parser.add_argument("--no-patches", action="store_true", help="Skip patch generation")
    parser.add_argument("--fail-on", default="high", choices=list(_SEV),
                        help="Exit 2 if a finding is at/above this severity")
    parser.add_argument("--model-mode", default=config.MODEL_MODE,
                        choices=["off", "auto", "on"], help="Detection model mode")
    args = parser.parse_args(argv)

    try:
        if args.repo:
            source = {"type": "repo", "url": args.repo, "branch": args.branch, "commit": args.commit}
            target = args.repo
        else:
            path = args.code_file or args.path
            if not path:
                parser.error("provide a path, --code-file, or --repo")
            root = Path(path)
            source = collect_path(root)
            target = str(root)

        scan = Scan(
            id=uuid.uuid4().hex,
            target=target,
            source_type=source["type"],
            config={
                "generate_patches": not args.no_patches,
                "model_mode": args.model_mode,
            },
        )
        run_scan(scan, source)
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


def _print_text(scan: Scan) -> None:
    print(f"CodeShield AI scan {scan.id} — {scan.target}")
    print(f"files={scan.summary.files_scanned} units={scan.summary.units_scanned} "
          f"findings={scan.summary.total_findings} model={'yes' if scan.summary.model_used else 'no'}")
    print(f"by severity: {scan.summary.by_severity}")
    print("-" * 78)
    for finding in sorted(scan.findings, key=lambda item: -_SEV.get(item.severity, 0)):
        print(f"[{finding.severity.upper():8s}] {finding.cwe} "
              f"{finding.path}:{finding.start_line} ({finding.function}) "
              f"engine={finding.engine} conf={finding.confidence:.0%}")
        print(f"           {finding.message}")
        for candidate in finding.patch_candidates[:1]:
            print(f"           patch[{candidate.verification}] {candidate.summary}")
    if not scan.findings:
        print("No findings.")


if __name__ == "__main__":
    raise SystemExit(main())
