#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"

CONFIGURATION="${CONFIGURATION:-Debug}"
DIST_DIR="$ROOT_DIR/dist"
APP_NAME="NmapGUI.app"
ZIP_NAME="NmapGUI-macOS-arm64-dev.zip"

echo "Building NmapGUI..."
xcodebuild \
  -project NmapMac.xcodeproj \
  -scheme NmapGUI \
  -configuration "$CONFIGURATION" \
  clean build

echo
echo "Packaging bundled dylibs..."
bash xcode/scripts/package-nmapgui-macos.sh

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
"$DIST_DIR/$APP_NAME/Contents/Resources/nmap" --version
otool -L "$DIST_DIR/$APP_NAME/Contents/Resources/nmap"

if otool -L "$DIST_DIR/$APP_NAME/Contents/Resources/nmap" | grep -q "/opt/homebrew"; then
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
