#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"

CONFIGURATION="${CONFIGURATION:-Debug}"
DERIVED_DATA_PATH="${DERIVED_DATA_PATH:-}"
APP_PATH="${APP_PATH:-}"

if [ -z "$APP_PATH" ]; then
  if [ -n "$DERIVED_DATA_PATH" ]; then
    APP_PATH="$DERIVED_DATA_PATH/Build/Products/$CONFIGURATION/Zenmap.app"
  else
    APP_PATH="$(find "$HOME/Library/Developer/Xcode/DerivedData" \
      -path "*/Build/Products/$CONFIGURATION/Zenmap.app" \
      -not -path "*/Index.noindex/*" \
      -type d \
      -print 2>/dev/null | sort | tail -n 1)"
  fi
fi

if [ -z "$APP_PATH" ] || [ ! -d "$APP_PATH" ]; then
  echo "error: Zenmap.app was not found. Build the Zenmap scheme first, or pass APP_PATH=/path/to/Zenmap.app." >&2
  exit 1
fi

CONTENTS_DIR="$APP_PATH/Contents"
RESOURCES_DIR="$CONTENTS_DIR/Resources"
FRAMEWORKS_DIR="$CONTENTS_DIR/Frameworks"
if [ -x "$RESOURCES_DIR/bin/nmap" ]; then
  NMAP_BIN="$RESOURCES_DIR/bin/nmap"
elif [ -x "$RESOURCES_DIR/nmap" ]; then
  NMAP_BIN="$RESOURCES_DIR/nmap"
else
  NMAP_BIN="$RESOURCES_DIR/bin/nmap"
fi
NMAP_SHARE="$RESOURCES_DIR/share/nmap"
SIGN_IDENTITY="${SIGN_IDENTITY:--}"

if [ ! -x "$NMAP_BIN" ]; then
  echo "error: bundled nmap binary not found or not executable: $NMAP_BIN" >&2
  exit 1
fi

if [ ! -f "$NMAP_SHARE/nmap-services" ]; then
  echo "error: bundled nmap-services not found: $NMAP_SHARE/nmap-services" >&2
  exit 1
fi

if [ ! -f "$NMAP_SHARE/scripts/script.db" ]; then
  echo "error: bundled NSE script database not found: $NMAP_SHARE/scripts/script.db" >&2
  exit 1
fi

mkdir -p "$FRAMEWORKS_DIR"

ZENMAP_ICON="$ROOT_DIR/zenmap/install_scripts/macosx/zenmap.icns"
if [ -f "$ZENMAP_ICON" ]; then
  cp "$ZENMAP_ICON" "$RESOURCES_DIR/zenmap.icns"
  /usr/libexec/PlistBuddy -c "Set :CFBundleIconFile zenmap.icns" "$CONTENTS_DIR/Info.plist" 2>/dev/null || \
    /usr/libexec/PlistBuddy -c "Add :CFBundleIconFile string zenmap.icns" "$CONTENTS_DIR/Info.plist"
else
  echo "warning: optional Zenmap app icon missing: $ZENMAP_ICON"
fi


OPENSSL_PREFIX="${OPENSSL_PREFIX:-}"
LIBSSH2_PREFIX="${LIBSSH2_PREFIX:-}"

if [ -z "$OPENSSL_PREFIX" ] && command -v brew >/dev/null 2>&1; then
  OPENSSL_PREFIX="$(brew --prefix openssl@3 2>/dev/null || true)"
fi

if [ -z "$LIBSSH2_PREFIX" ] && command -v brew >/dev/null 2>&1; then
  LIBSSH2_PREFIX="$(brew --prefix libssh2 2>/dev/null || true)"
fi

copy_dylib() {
  local source_path="$1"
  local destination_name
  destination_name="$(basename "$source_path")"

  if [ ! -f "$source_path" ]; then
    echo "error: dylib not found: $source_path" >&2
    exit 1
  fi

  echo "Copying $destination_name"
  cp -f "$source_path" "$FRAMEWORKS_DIR/$destination_name"
  chmod 755 "$FRAMEWORKS_DIR/$destination_name"
}

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

copy_dylib "$SSL_DYLIB"
copy_dylib "$CRYPTO_DYLIB"
copy_dylib "$SSH2_DYLIB"

SSL_NAME="$(basename "$SSL_DYLIB")"
CRYPTO_NAME="$(basename "$CRYPTO_DYLIB")"
SSH2_NAME="$(basename "$SSH2_DYLIB")"

rewrite_dependency() {
  local binary_path="$1"
  local old_path="$2"
  local new_path="$3"

  if otool -L "$binary_path" | grep -Fq "$old_path"; then
    install_name_tool -change "$old_path" "$new_path" "$binary_path"
  fi
}

set_id() {
  local binary_path="$1"
  local id_path="$2"
  install_name_tool -id "$id_path" "$binary_path" || true
}

SSL_BUNDLED="$FRAMEWORKS_DIR/$SSL_NAME"
CRYPTO_BUNDLED="$FRAMEWORKS_DIR/$CRYPTO_NAME"
SSH2_BUNDLED="$FRAMEWORKS_DIR/$SSH2_NAME"

set_id "$SSL_BUNDLED" "@rpath/$SSL_NAME"
set_id "$CRYPTO_BUNDLED" "@rpath/$CRYPTO_NAME"
set_id "$SSH2_BUNDLED" "@rpath/$SSH2_NAME"

NMAP_RELATIVE_FRAMEWORKS="@executable_path/../../Frameworks"
if [ "$(dirname "$NMAP_BIN")" = "$RESOURCES_DIR" ]; then
  NMAP_RELATIVE_FRAMEWORKS="@executable_path/../Frameworks"
fi

rewrite_dependency "$NMAP_BIN" "$SSL_DYLIB" "$NMAP_RELATIVE_FRAMEWORKS/$SSL_NAME"
rewrite_dependency "$NMAP_BIN" "$CRYPTO_DYLIB" "$NMAP_RELATIVE_FRAMEWORKS/$CRYPTO_NAME"
rewrite_dependency "$NMAP_BIN" "$SSH2_DYLIB" "$NMAP_RELATIVE_FRAMEWORKS/$SSH2_NAME"

# Correct stale relative paths left by earlier package runs.
rewrite_dependency "$NMAP_BIN" "@executable_path/../Frameworks/$SSL_NAME" "$NMAP_RELATIVE_FRAMEWORKS/$SSL_NAME"
rewrite_dependency "$NMAP_BIN" "@executable_path/../Frameworks/$CRYPTO_NAME" "$NMAP_RELATIVE_FRAMEWORKS/$CRYPTO_NAME"
rewrite_dependency "$NMAP_BIN" "@executable_path/../Frameworks/$SSH2_NAME" "$NMAP_RELATIVE_FRAMEWORKS/$SSH2_NAME"
rewrite_dependency "$NMAP_BIN" "@executable_path/../../Frameworks/$SSL_NAME" "$NMAP_RELATIVE_FRAMEWORKS/$SSL_NAME"
rewrite_dependency "$NMAP_BIN" "@executable_path/../../Frameworks/$CRYPTO_NAME" "$NMAP_RELATIVE_FRAMEWORKS/$CRYPTO_NAME"
rewrite_dependency "$NMAP_BIN" "@executable_path/../../Frameworks/$SSH2_NAME" "$NMAP_RELATIVE_FRAMEWORKS/$SSH2_NAME"

rewrite_dependency "$SSL_BUNDLED" "$CRYPTO_DYLIB" "@loader_path/$CRYPTO_NAME"
rewrite_dependency "$SSH2_BUNDLED" "$SSL_DYLIB" "@loader_path/$SSL_NAME"
rewrite_dependency "$SSH2_BUNDLED" "$CRYPTO_DYLIB" "@loader_path/$CRYPTO_NAME"

install_name_tool -add_rpath "$NMAP_RELATIVE_FRAMEWORKS" "$NMAP_BIN" 2>/dev/null || true

codesign --force --sign "$SIGN_IDENTITY" "$SSL_BUNDLED" >/dev/null
codesign --force --sign "$SIGN_IDENTITY" "$CRYPTO_BUNDLED" >/dev/null
codesign --force --sign "$SIGN_IDENTITY" "$SSH2_BUNDLED" >/dev/null
codesign --force --sign "$SIGN_IDENTITY" "$NMAP_BIN" >/dev/null
codesign --force --deep --options runtime --sign "$SIGN_IDENTITY" "$APP_PATH" >/dev/null

echo
echo "Packaged app: $APP_PATH"
echo
echo "Bundled libraries:"
ls -lh "$FRAMEWORKS_DIR"/*.dylib

echo
echo "nmap dependencies:"
otool -L "$NMAP_BIN"

echo
echo "Verification:"
echo "Using nmap binary: $NMAP_BIN"
echo "Using NMAPDIR: $NMAP_SHARE"
NMAPDIR="$NMAP_SHARE" "$NMAP_BIN" --datadir "$NMAP_SHARE" --version
codesign --verify --deep --strict --verbose=2 "$APP_PATH"
