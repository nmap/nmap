#!/bin/sh
set -eu

# Build upstream Nmap from an Xcode External Build Tool target.
# Expected layout: this overlay is copied into the root of an upstream nmap checkout.
# You may override these from Xcode build settings or the shell.

ROOT_DIR="${NMAP_SOURCE_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
BUILD_DIR="${NMAP_BUILD_DIR:-$ROOT_DIR/.xcode-build/nmap}"
INSTALL_DIR="${NMAP_INSTALL_DIR:-$ROOT_DIR/.xcode-products/nmap-root}"
CONFIGURE_FLAGS="${NMAP_CONFIGURE_FLAGS:---prefix=/usr/local}"
JOBS="${NMAP_BUILD_JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 4)}"

mkdir -p "$BUILD_DIR" "$INSTALL_DIR"
cd "$ROOT_DIR"

if [ ! -x ./configure ]; then
  echo "error: ./configure not found. Copy this overlay into the root of an upstream nmap checkout." >&2
  exit 1
fi

# Nmap's source tree is autotools/Makefile based. Configure in-tree by default because
# upstream Nmap has historically expected that path more reliably than out-of-tree builds.
if [ ! -f Makefile ]; then
  echo "Configuring Nmap..."
  ./configure $CONFIGURE_FLAGS
fi

echo "Building Nmap with $JOBS jobs..."
make -j"$JOBS"

echo "Staging install into $INSTALL_DIR..."
make install DESTDIR="$INSTALL_DIR"

echo "Built binary: $ROOT_DIR/nmap"
echo "Staged install root: $INSTALL_DIR"
