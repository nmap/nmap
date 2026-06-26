#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
PKG_DIR="$DIST_DIR/pkg"
DMG_ROOT="$DIST_DIR/dmg-root"

COMPLETE_PKG="$PKG_DIR/NmapComplete.pkg"
CLI_PKG="$PKG_DIR/NmapCLI.pkg"
GUI_PKG="$PKG_DIR/ZenmapOnly.pkg"

ARCH="$(uname -m)"
NMAP_VERSION="${NMAP_VERSION:-}"

if [ -z "$NMAP_VERSION" ]; then
  if [ -x "$ROOT_DIR/nmap" ]; then
    NMAP_VERSION="$("$ROOT_DIR/nmap" --version | awk '/Nmap version/ { print $3; exit }')"
  elif command -v nmap >/dev/null 2>&1; then
    NMAP_VERSION="$(nmap --version | awk '/Nmap version/ { print $3; exit }')"
  else
    NMAP_VERSION="7.99SVN"
  fi
fi

VOLNAME="Nmap ${NMAP_VERSION} for macOS"
DMG_NAME="nmap-${NMAP_VERSION}-macOS-${ARCH}.dmg"
DMG_PATH="$DIST_DIR/$DMG_NAME"

for pkg in "$COMPLETE_PKG" "$CLI_PKG" "$GUI_PKG"; do
  if [ ! -f "$pkg" ]; then
    echo "Missing $pkg"
    echo "Build packages first with:"
    echo "  bash macosx/release-nmap-cli-macos.sh"
    echo "  bash macosx/release-zenmap-macos.sh"
    echo "  bash macosx/pkg-nmap-macos.sh"
    exit 1
  fi
done

rm -rf "$DMG_ROOT"
mkdir -p "$DMG_ROOT"

cp "$COMPLETE_PKG" "$DMG_ROOT/NmapComplete.pkg"
cp "$CLI_PKG" "$DMG_ROOT/NmapCLI.pkg"
cp "$GUI_PKG" "$DMG_ROOT/ZenmapOnly.pkg"

if [ -f "$ROOT_DIR/README.md" ]; then
  cp "$ROOT_DIR/README.md" "$DMG_ROOT/README.md"
elif [ -f "$ROOT_DIR/README" ]; then
  cp "$ROOT_DIR/README" "$DMG_ROOT/README"
fi

if [ -f "$ROOT_DIR/LICENSE" ]; then
  cp "$ROOT_DIR/LICENSE" "$DMG_ROOT/LICENSE"
elif [ -f "$ROOT_DIR/COPYING" ]; then
  cp "$ROOT_DIR/COPYING" "$DMG_ROOT/COPYING"
fi

cat > "$DMG_ROOT/Install Nmap.txt" <<INSTALLTXT
Nmap ${NMAP_VERSION} for macOS

Choose one installer:

NmapComplete.pkg
  Installs Nmap, Ncat, Nping, Ndiff, and Zenmap.

NmapCLI.pkg
  Installs command-line tools only:
  nmap, ncat, nping, and ndiff.

ZenmapOnly.pkg
  Installs Zenmap only.

Recommended install:
  Double-click NmapComplete.pkg.

Terminal install examples:

sudo installer -pkg "/Volumes/${VOLNAME}/NmapComplete.pkg" -target /
sudo installer -pkg "/Volumes/${VOLNAME}/NmapCLI.pkg" -target /
sudo installer -pkg "/Volumes/${VOLNAME}/ZenmapOnly.pkg" -target /

After installation:

nmap --version
ncat --version
nping --version
ndiff -h
open /Applications/Zenmap.app
INSTALLTXT

xattr -cr "$DMG_ROOT" 2>/dev/null || true
dot_clean -m "$DMG_ROOT" 2>/dev/null || true
find "$DMG_ROOT" -name '._*' -delete 2>/dev/null || true

rm -f "$DMG_PATH"

hdiutil create \
  -volname "$VOLNAME" \
  -srcfolder "$DMG_ROOT" \
  -ov \
  -format UDZO \
  "$DMG_PATH"

hdiutil verify "$DMG_PATH"

echo
echo "DMG created:"
ls -lh "$DMG_PATH"
echo
echo "DMG payload:"
find "$DMG_ROOT" -maxdepth 1 -type f -print | sed "s#^$DMG_ROOT/##" | sort
