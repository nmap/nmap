#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"

CONFIGURATION="${CONFIGURATION:-Debug}"
DIST_DIR="$ROOT_DIR/dist"
CLI_APP="$DIST_DIR/nmap.app"
CONTENTS_DIR="$CLI_APP/Contents"
RESOURCES_DIR="$CONTENTS_DIR/Resources"
BIN_DIR="$RESOURCES_DIR/bin"
SHARE_DIR="$RESOURCES_DIR/share"
NMAP_SHARE_DIR="$SHARE_DIR/nmap"
MAN_DIR="$SHARE_DIR/man/man1"
LIB_DIR="$RESOURCES_DIR/lib"
ZIP_NAME="nmap-macOS-arm64-dev.zip"

echo "Building native NmapCLI..."
xcodebuild \
  -project NmapMac.xcodeproj \
  -scheme NmapCLI \
  -configuration "$CONFIGURATION" \
  build

if [ ! -x "$ROOT_DIR/nmap" ]; then
  echo "error: native nmap binary not found at $ROOT_DIR/nmap" >&2
  exit 1
fi

echo
echo "Creating current-installer-style nmap.app bundle..."
rm -rf "$CLI_APP"
mkdir -p "$BIN_DIR" "$NMAP_SHARE_DIR" "$MAN_DIR" "$LIB_DIR"

cat > "$CONTENTS_DIR/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>nmap</string>
  <key>CFBundleIdentifier</key>
  <string>org.nmap.nmap</string>
  <key>CFBundleName</key>
  <string>nmap</string>
  <key>CFBundleDisplayName</key>
  <string>Nmap</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>7.99SVN</string>
  <key>CFBundleVersion</key>
  <string>7.99SVN</string>
  <key>LSMinimumSystemVersion</key>
  <string>26.5</string>
</dict>
</plist>
PLIST

cp "$ROOT_DIR/nmap" "$BIN_DIR/nmap"
chmod 755 "$BIN_DIR/nmap"

copy_data_file() {
  local source="$1"
  local destination="$2"

  if [ -e "$source" ]; then
    cp "$source" "$destination"
  else
    echo "warning: missing optional data file: $source"
  fi
}

copy_data_file "$ROOT_DIR/nmap-services" "$NMAP_SHARE_DIR/"
copy_data_file "$ROOT_DIR/nmap-protocols" "$NMAP_SHARE_DIR/"
copy_data_file "$ROOT_DIR/nmap-rpc" "$NMAP_SHARE_DIR/"
copy_data_file "$ROOT_DIR/nmap-mac-prefixes" "$NMAP_SHARE_DIR/"
copy_data_file "$ROOT_DIR/nmap-os-db" "$NMAP_SHARE_DIR/"
copy_data_file "$ROOT_DIR/nmap-service-probes" "$NMAP_SHARE_DIR/"
copy_data_file "$ROOT_DIR/docs/nmap.dtd" "$NMAP_SHARE_DIR/nmap.dtd"
copy_data_file "$ROOT_DIR/nse_main.lua" "$NMAP_SHARE_DIR/"

if [ -d "$ROOT_DIR/scripts" ]; then
  cp -R "$ROOT_DIR/scripts" "$NMAP_SHARE_DIR/scripts"
else
  echo "warning: scripts directory missing"
fi

if [ -d "$ROOT_DIR/nselib" ]; then
  cp -R "$ROOT_DIR/nselib" "$NMAP_SHARE_DIR/nselib"
else
  echo "warning: nselib directory missing"
fi

if [ -f "$ROOT_DIR/docs/nmap.1" ]; then
  cp "$ROOT_DIR/docs/nmap.1" "$MAN_DIR/nmap.1"
elif [ -f "$ROOT_DIR/.xcode-products/nmap-root/usr/local/share/man/man1/nmap.1" ]; then
  cp "$ROOT_DIR/.xcode-products/nmap-root/usr/local/share/man/man1/nmap.1" "$MAN_DIR/nmap.1"
else
  echo "warning: nmap man page not found"
fi

OPENSSL_PREFIX="${OPENSSL_PREFIX:-}"
LIBSSH2_PREFIX="${LIBSSH2_PREFIX:-}"

if [ -z "$OPENSSL_PREFIX" ] && command -v brew >/dev/null 2>&1; then
  OPENSSL_PREFIX="$(brew --prefix openssl@3 2>/dev/null || true)"
fi

if [ -z "$LIBSSH2_PREFIX" ] && command -v brew >/dev/null 2>&1; then
  LIBSSH2_PREFIX="$(brew --prefix libssh2 2>/dev/null || true)"
fi

if [ -z "$OPENSSL_PREFIX" ] || [ ! -d "$OPENSSL_PREFIX" ]; then
  echo "error: openssl@3 prefix not found. Install with: brew install openssl@3" >&2
  exit 1
fi

if [ -z "$LIBSSH2_PREFIX" ] || [ ! -d "$LIBSSH2_PREFIX" ]; then
  echo "error: libssh2 prefix not found. Install with: brew install libssh2" >&2
  exit 1
fi

SSL_DYLIB="$(find "$OPENSSL_PREFIX/lib" -maxdepth 1 -name 'libssl.*.dylib' | sort | tail -n 1)"
CRYPTO_DYLIB="$(find "$OPENSSL_PREFIX/lib" -maxdepth 1 -name 'libcrypto.*.dylib' | sort | tail -n 1)"
SSH2_DYLIB="$(find "$LIBSSH2_PREFIX/lib" -maxdepth 1 -name 'libssh2.*.dylib' | sort | tail -n 1)"

cp "$SSL_DYLIB" "$LIB_DIR/"
cp "$CRYPTO_DYLIB" "$LIB_DIR/"
cp "$SSH2_DYLIB" "$LIB_DIR/"

SSL_NAME="$(basename "$SSL_DYLIB")"
CRYPTO_NAME="$(basename "$CRYPTO_DYLIB")"
SSH2_NAME="$(basename "$SSH2_DYLIB")"

NMAP_BIN="$BIN_DIR/nmap"
SSL_BUNDLED="$LIB_DIR/$SSL_NAME"
CRYPTO_BUNDLED="$LIB_DIR/$CRYPTO_NAME"
SSH2_BUNDLED="$LIB_DIR/$SSH2_NAME"

rewrite_dependency() {
  local binary_path="$1"
  local old_path="$2"
  local new_path="$3"

  if otool -L "$binary_path" | grep -Fq "$old_path"; then
    install_name_tool -change "$old_path" "$new_path" "$binary_path"
  fi
}

install_name_tool -id "@rpath/$SSL_NAME" "$SSL_BUNDLED" || true
install_name_tool -id "@rpath/$CRYPTO_NAME" "$CRYPTO_BUNDLED" || true
install_name_tool -id "@rpath/$SSH2_NAME" "$SSH2_BUNDLED" || true

rewrite_dependency "$NMAP_BIN" "$SSL_DYLIB" "@executable_path/../lib/$SSL_NAME"
rewrite_dependency "$NMAP_BIN" "$CRYPTO_DYLIB" "@executable_path/../lib/$CRYPTO_NAME"
rewrite_dependency "$NMAP_BIN" "$SSH2_DYLIB" "@executable_path/../lib/$SSH2_NAME"

rewrite_dependency "$SSL_BUNDLED" "$CRYPTO_DYLIB" "@loader_path/$CRYPTO_NAME"
rewrite_dependency "$SSH2_BUNDLED" "$SSL_DYLIB" "@loader_path/$SSL_NAME"
rewrite_dependency "$SSH2_BUNDLED" "$CRYPTO_DYLIB" "@loader_path/$CRYPTO_NAME"

install_name_tool -add_rpath "@executable_path/../lib" "$NMAP_BIN" 2>/dev/null || true

codesign --force --sign - "$SSL_BUNDLED" >/dev/null
codesign --force --sign - "$CRYPTO_BUNDLED" >/dev/null
codesign --force --sign - "$SSH2_BUNDLED" >/dev/null
codesign --force --sign - "$NMAP_BIN" >/dev/null
codesign --force --deep --sign - "$CLI_APP" >/dev/null

echo
echo "Verifying current-installer-style CLI bundle..."
"$NMAP_BIN" --version
otool -L "$NMAP_BIN"

if otool -L "$NMAP_BIN" | grep -q "/opt/homebrew"; then
  echo "error: CLI bundle still references Homebrew dylibs" >&2
  exit 1
fi

echo
echo "Smoke testing bundled data path..."
NMAPDIR="$NMAP_SHARE_DIR" "$NMAP_BIN" -sV --version >/dev/null

echo
echo "Creating CLI zip..."
rm -f "$DIST_DIR/$ZIP_NAME"
(
  cd "$DIST_DIR"
  ditto -c -k --keepParent "nmap.app" "$ZIP_NAME"
)

echo
echo "CLI release artifact:"
ls -lh "$DIST_DIR/$ZIP_NAME"

echo
echo "Done: $DIST_DIR/$ZIP_NAME"
