"""CodeShield AI command-line interface (PRD §7.7, adapted from the strix CLI usage).

    codeshield scan <path|file|github-url> [--fail-on high]
    codeshield serve [--host H] [--port P]
    codeshield version
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .config import get_settings
from .core.ingestion import ingest_directory, ingest_github, read_file
from .core.scan import Scanner, ScanOptions
from .models import ScanResult, Severity
from .report import to_json, to_pdf, to_sarif_str


def _resolve_files(target: str, settings):
    if target.startswith(("http://", "https://", "git@")):
        files, _path = ingest_github(target, settings=settings)
        return files, target
    if os.path.isdir(target):
        return ingest_directory(target, settings), target
    if os.path.isfile(target):
        return [read_file(target, settings=settings)], target
    raise SystemExit(f"error: no such file, directory or GitHub URL: {target}")


def _print_table(scan: ScanResult) -> None:
    summary = scan.summary
    print(f"\nCodeShield AI — scan {scan.id}")
    print(f"  source: {scan.source}")
    print(f"  model:  {scan.model_version or 'rules only'}")
    print(
        f"  files:  {summary.files_scanned} scanned / {summary.files_skipped} skipped\n"
        f"  findings: {summary.total_findings}"
        + "".join(
            f"  {sev}={count}" for sev, count in summary.by_severity.items() if count
        )
    )
    if scan.engine_notes:
        print("\n  engine notes:")
        for note in scan.engine_notes:
            print(f"    - {note}")

    if not scan.findings:
        print("\n  No findings. (Absence of findings is not a guarantee of security.)\n")
        return

    patches = {p.finding_id: p for p in scan.patches}
    print("\n  Findings")
    print(f"  {'SEV':<9} {'CWE':<9} {'CONF':<6} {'ENGINE':<7} LOCATION — TITLE")
    for finding in scan.findings:
        location = f"{finding.file}:{finding.location.start_line}"
        print(
            f"  {finding.severity.value:<9} {finding.cwe:<9} {finding.confidence:<6.2f} "
            f"{finding.engine.value:<7} {location} — {finding.title}"
        )
        patch = patches.get(finding.id)
        if patch:
            print(f"      patch [{patch.status.value}] {patch.summary}")
    print()


def _cmd_scan(args: argparse.Namespace) -> int:
    settings = get_settings()
    if args.no_model:
        settings.disable_model = True
    if args.threshold is not None:
        settings.model_threshold = args.threshold

    suppress: set[str] = set()
    if args.suppress and os.path.isfile(args.suppress):
        with open(args.suppress, encoding="utf-8") as handle:
            suppress = {line.strip() for line in handle if line.strip()}

    files, source = _resolve_files(args.target, settings)
    options = ScanOptions(settings=settings, suppress_fingerprints=suppress, run_tests=args.run_tests)

    def progress(index: int, total: int, path: str) -> None:
        if not args.quiet and sys.stderr.isatty():
            sys.stderr.write(f"\r  scanning {index}/{total}: {path[:60]:<60}")
            sys.stderr.flush()

    scan = Scanner(options).scan(files, source, progress=progress)
    if not args.quiet and sys.stderr.isatty():
        sys.stderr.write("\r" + " " * 80 + "\r")

    if args.write_suppress:
        fingerprints = sorted({f.fingerprint for f in scan.findings if f.fingerprint})
        with open(args.write_suppress, "w", encoding="utf-8") as handle:
            handle.write("\n".join(fingerprints) + "\n")
        print(f"wrote {len(fingerprints)} fingerprint(s) to {args.write_suppress}")

    if args.format == "json":
        output = to_json(scan)
    elif args.format == "sarif":
        output = to_sarif_str(scan)
    elif args.format == "pdf":
        data = to_pdf(scan)
        if args.output:
            with open(args.output, "wb") as handle:
                handle.write(data)
            print(f"wrote {args.output}")
            return _exit_code(scan, args.fail_on)
        sys.stdout.buffer.write(data)
        return _exit_code(scan, args.fail_on)
    else:
        _print_table(scan)
        output = None

    if output is not None and args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(output)
        print(f"wrote {args.output}")
    elif output is not None:
        print(output)

    return _exit_code(scan, args.fail_on)


def _exit_code(scan: ScanResult, fail_on: str | None) -> int:
    if not fail_on:
        return 0
    threshold = Severity(fail_on)
    worst = max((f.severity.rank for f in scan.findings), default=-1)
    if worst >= threshold.rank:
        print(
            f"CodeShield: findings at or above '{fail_on}' severity block the build.",
            file=sys.stderr,
        )
        return 1
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    settings = get_settings()
    if args.no_model:
        os.environ["CODESHIELD_DISABLE_MODEL"] = "1"
    host = args.host or settings.host
    port = args.port or settings.port
    print(f"CodeShield AI dashboard on http://{host}:{port}")
    uvicorn.run("codeshield.api.app:app", host=host, port=port, reload=args.reload, log_level="info")
    return 0


def _cmd_version(_args: argparse.Namespace) -> int:
    settings = get_settings()
    print(json.dumps({"codeshield": __version__, "model_id": settings.model_id}, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codeshield",
        description="AI-powered source code vulnerability scanner & explainable auto-repair engine",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a file, directory, .zip or public GitHub repo")
    scan.add_argument("target", help="path, directory or https://github.com/owner/repo URL")
    scan.add_argument(
        "--format", choices=["table", "json", "sarif", "pdf"], default="table", help="output format"
    )
    scan.add_argument("--output", "-o", help="write the report to a file")
    scan.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        help="exit non-zero when a finding at or above this severity exists (CI gate)",
    )
    scan.add_argument("--suppress", help="file of fingerprints to suppress (false-positive memory)")
    scan.add_argument(
        "--write-suppress",
        metavar="FILE",
        help="write the current findings' fingerprints to FILE (baseline the existing state)",
    )
    scan.add_argument("--threshold", type=float, help="model confidence threshold")
    scan.add_argument("--no-model", action="store_true", help="rules-only, skip the neural detector")
    scan.add_argument("--run-tests", action="store_true", help="run project tests in the sandbox if available")
    scan.add_argument("--quiet", "-q", action="store_true", help="suppress progress output")
    scan.set_defaults(func=_cmd_scan)

    serve = sub.add_parser("serve", help="run the web dashboard + REST API")
    serve.add_argument("--host", help="bind host")
    serve.add_argument("--port", type=int, help="bind port")
    serve.add_argument("--reload", action="store_true", help="auto-reload on code changes")
    serve.add_argument("--no-model", action="store_true", help="rules-only")
    serve.set_defaults(func=_cmd_serve)

    version = sub.add_parser("version", help="print version and model id")
    version.set_defaults(func=_cmd_version)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
