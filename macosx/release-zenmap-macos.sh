#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

CONFIGURATION="${CONFIGURATION:-Debug}"
DIST_DIR="$ROOT_DIR/dist"
APP_NAME="Zenmap.app"
ZIP_NAME="zenmap-macOS-arm64-dev.zip"

echo "Building Zenmap..."
xcodebuild \
  -project NmapMac.xcodeproj \
  -scheme Zenmap \
  -configuration "$CONFIGURATION" \
  clean build

echo
echo "Packaging bundled dylibs..."
bash macosx/package-zenmap-macos.sh

APP_PATH="$(find "$HOME/Library/Developer/Xcode/DerivedData" \
  -path "*/Build/Products/$CONFIGURATION/$APP_NAME" \
  -not -path "*/Index.noindex/*" \
  -type d \
  -print 2>/dev/null | sort | tail -n 1)"

if [ -z "$APP_PATH" ] || [ ! -d "$APP_PATH" ]; then
  echo "error: packaged app not found" >&2
  exit 1
fi

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

echo
echo "Copying app to dist..."
cp -R "$APP_PATH" "$DIST_DIR/$APP_NAME"

echo
echo "Verifying copied app..."
if [ -x "$DIST_DIR/$APP_NAME/Contents/Resources/bin/nmap" ]; then
  NMAP_BIN="$DIST_DIR/$APP_NAME/Contents/Resources/bin/nmap"
elif [ -x "$DIST_DIR/$APP_NAME/Contents/Resources/nmap" ]; then
  NMAP_BIN="$DIST_DIR/$APP_NAME/Contents/Resources/nmap"
else
  echo "error: copied app does not contain an executable nmap binary" >&2
  exit 1
fi
NMAP_SHARE="$DIST_DIR/$APP_NAME/Contents/Resources/share/nmap"

if [ ! -f "$NMAP_SHARE/nmap-services" ]; then
  echo "error: copied app is missing bundled nmap-services" >&2
  exit 1
fi

if [ ! -f "$NMAP_SHARE/scripts/script.db" ]; then
  echo "error: copied app is missing bundled NSE script database" >&2
  exit 1
fi

NMAPDIR="$NMAP_SHARE" "$NMAP_BIN" --datadir "$NMAP_SHARE" --version
otool -L "$NMAP_BIN"

if otool -L "$NMAP_BIN" | grep -q "/opt/homebrew"; then
  echo "error: copied app still references Homebrew dylibs" >&2
  exit 1
fi

echo
echo "Creating zip..."
(
  cd "$DIST_DIR"
  ditto -c -k --keepParent "$APP_NAME" "$ZIP_NAME"
)

echo
echo "Release artifact:"
ls -lh "$DIST_DIR/$ZIP_NAME"

echo
echo "Done: $DIST_DIR/$ZIP_NAME"
