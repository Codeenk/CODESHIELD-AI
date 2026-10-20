#!/usr/bin/env bash
# Install a prebuilt llama.cpp CPU server into .tools/ (gitignored).
set -euo pipefail

TAG="${LLAMA_TAG:-b11753}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEST="$ROOT/.tools/llama-$TAG"
ASSET="llama-$TAG-bin-ubuntu-x64.tar.gz"
URL="https://github.com/ggml-org/llama.cpp/releases/download/$TAG/$ASSET"

if [[ -x "$DEST/llama-server" ]]; then
  echo "llama-server already installed: $DEST/llama-server"
  exit 0
fi

mkdir -p "$ROOT/.tools"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
echo "downloading $URL"
curl -fL --retry 3 "$URL" -o "$tmp/llama.tar.gz"
tar -xzf "$tmp/llama.tar.gz" -C "$ROOT/.tools"
echo "installed: $DEST/llama-server"
