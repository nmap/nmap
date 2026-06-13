#!/bin/sh
set -eu
ROOT_DIR="${NMAP_SOURCE_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$ROOT_DIR"
if [ -f Makefile ]; then
  make clean || true
fi
rm -rf "$ROOT_DIR/.xcode-build" "$ROOT_DIR/.xcode-products"
echo "Cleaned Xcode Nmap build artifacts."
