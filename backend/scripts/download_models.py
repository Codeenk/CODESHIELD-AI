#!/usr/bin/env python
"""Download optional local model weights for CodeShield AI.

Usage:
    python backend/scripts/download_models.py --all
    python backend/scripts/download_models.py --detector
    python backend/scripts/download_models.py --repair

The detector is CodeBERT (~476 MB). The repair model is Qwen2.5-Coder-1.5B
Instruct in GGUF Q4_K_M (~1.1 GB) and is served by llama.cpp.
"""
from __future__ import annotations

import argparse
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MODELS = REPO / "models"
DETECTOR_REPO = "mrm8488/codebert-base-finetuned-detect-insecure-code"
DETECTOR_FILES = [
    "config.json",
    "merges.txt",
    "special_tokens_map.json",
    "tokenizer_config.json",
    "vocab.json",
    "pytorch_model.bin",
]
REPAIR_FILE = "qwen2.5-coder-1.5b-instruct-q4_k_m.gguf"
REPAIR_REPO = "Qwen/Qwen2.5-Coder-1.5B-Instruct-GGUF"


def _url(repo: str, filename: str) -> str:
    return f"https://huggingface.co/{repo}/resolve/main/{filename}?download=true"


def _size(url: str) -> int:
    request = urllib.request.Request(url, method="HEAD")
    token = os.environ.get("HF_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=60) as response:
        return int(response.headers.get("Content-Length", "0"))


def download(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    expected = 0
    try:
        expected = _size(url)
    except (urllib.error.URLError, OSError):
        pass
    if destination.exists() and expected and destination.stat().st_size == expected:
        print(f"ok        {destination.relative_to(REPO)} ({expected / 1e6:.0f} MB)")
        return
    partial = destination.with_suffix(destination.suffix + ".part")
    offset = partial.stat().st_size if partial.exists() else 0
    if expected and offset > expected:
        partial.unlink()
        offset = 0
    request = urllib.request.Request(url)
    token = os.environ.get("HF_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    if offset:
        request.add_header("Range", f"bytes={offset}-")
    mode = "ab" if offset else "wb"
    print(f"fetching  {destination.relative_to(REPO)} from {offset / 1e6:.0f} MB")
    try:
        with urllib.request.urlopen(request, timeout=120) as response, partial.open(mode) as handle:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                handle.write(chunk)
    except Exception:
        print(f"failed: partial file kept at {partial}", file=sys.stderr)
        raise
    partial.replace(destination)
    size = destination.stat().st_size
    print(f"saved     {destination.relative_to(REPO)} ({size / 1e6:.0f} MB)")


def detector(force: bool = False) -> None:
    target = MODELS / "detector"
    for filename in DETECTOR_FILES:
        path = target / filename
        if force and path.exists():
            path.unlink()
        download(_url(DETECTOR_REPO, filename), path)
    print(f"detector ready: {target}")


def repair(force: bool = False) -> None:
    target = MODELS / "repair" / REPAIR_FILE
    if force and target.exists():
        target.unlink()
    download(_url(REPAIR_REPO, REPAIR_FILE), target)
    print(f"repair model ready: {target}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--detector", action="store_true", help="download CodeBERT detector")
    parser.add_argument("--repair", action="store_true", help="download Qwen2.5-Coder GGUF")
    parser.add_argument("--all", action="store_true", help="download both models")
    parser.add_argument("--force", action="store_true", help="redownload existing files")
    args = parser.parse_args()
    if not (args.detector or args.repair or args.all):
        parser.print_help()
        return 1
    if args.all or args.detector:
        detector(args.force)
    if args.all or args.repair:
        repair(args.force)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
