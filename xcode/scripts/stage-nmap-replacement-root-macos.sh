#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"

DIST_DIR="$ROOT_DIR/dist"
REPLACEMENT_ROOT="$DIST_DIR/replacement-root"
APPLICATIONS_DIR="$REPLACEMENT_ROOT/Applications"
USR_LOCAL_DIR="$REPLACEMENT_ROOT/usr/local"

copy_if_exists() {
  local source="$1"
  local destination="$2"

  if [ -e "$source" ]; then
    mkdir -p "$(dirname "$destination")"
    cp -R "$source" "$destination"
  else
    echo "warning: missing optional file: $source"
  fi
}

make_cli_plist() {
  local plist="$1"
  local executable="$2"
  local identifier="$3"
  local name="$4"

  cat > "$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>$executable</string>
  <key>CFBundleIdentifier</key>
  <string>$identifier</string>
  <key>CFBundleName</key>
  <string>$name</string>
  <key>CFBundleDisplayName</key>
  <string>$name</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>7.99</string>
  <key>CFBundleVersion</key>
  <string>7.99</string>
</dict>
</plist>
PLIST
}

if [ ! -d "$DIST_DIR/nmap.app" ]; then
  echo "Missing dist/nmap.app; running CLI release first..."
  bash xcode/scripts/release-nmap-cli-macos.sh
fi

if [ ! -d "$DIST_DIR/nmap.app" ]; then
  echo "error: dist/nmap.app was not created" >&2
  exit 1
fi

echo "Creating replacement root..."
rm -rf "$REPLACEMENT_ROOT"
mkdir -p "$APPLICATIONS_DIR" "$USR_LOCAL_DIR/bin" "$USR_LOCAL_DIR/share/man/man1"

cp -R "$DIST_DIR/nmap.app" "$APPLICATIONS_DIR/nmap.app"

copy_if_exists "$ROOT_DIR/docs/nmap.xsl" "$APPLICATIONS_DIR/nmap.app/Contents/Resources/share/nmap/nmap.xsl"
copy_if_exists "$ROOT_DIR/docs/nmap.dtd" "$APPLICATIONS_DIR/nmap.app/Contents/Resources/share/nmap/nmap.dtd"

make_cli_plist "$APPLICATIONS_DIR/nmap.app/Info.plist" "nmap" "org.insecure.nmap" "nmap"
mkdir -p "$APPLICATIONS_DIR/nmap.app/Contents/MacOS"
cp "$APPLICATIONS_DIR/nmap.app/Contents/Resources/bin/nmap" "$APPLICATIONS_DIR/nmap.app/Contents/MacOS/nmap"
chmod 755 "$APPLICATIONS_DIR/nmap.app/Contents/MacOS/nmap"

if [ -x "$ROOT_DIR/ncat/ncat" ]; then
  echo "Creating ncat.app..."
  mkdir -p \
    "$APPLICATIONS_DIR/ncat.app/Contents/MacOS" \
    "$APPLICATIONS_DIR/ncat.app/Contents/Resources/bin" \
    "$APPLICATIONS_DIR/ncat.app/Contents/Resources/lib" \
    "$APPLICATIONS_DIR/ncat.app/Contents/Resources/share/ncat" \
    "$APPLICATIONS_DIR/ncat.app/Contents/Resources/share/man/man1"

  make_cli_plist "$APPLICATIONS_DIR/ncat.app/Info.plist" "ncat" "org.insecure.nmap.ncat" "ncat"
  cp "$ROOT_DIR/ncat/ncat" "$APPLICATIONS_DIR/ncat.app/Contents/MacOS/ncat"
  cp "$ROOT_DIR/ncat/ncat" "$APPLICATIONS_DIR/ncat.app/Contents/Resources/bin/ncat"
  chmod 755 "$APPLICATIONS_DIR/ncat.app/Contents/MacOS/ncat" "$APPLICATIONS_DIR/ncat.app/Contents/Resources/bin/ncat"
  copy_if_exists "$ROOT_DIR/ncat/certs/ca-bundle.crt" "$APPLICATIONS_DIR/ncat.app/Contents/Resources/share/ncat/ca-bundle.crt"
  copy_if_exists "$ROOT_DIR/ncat/docs/ncat.1" "$APPLICATIONS_DIR/ncat.app/Contents/Resources/share/man/man1/ncat.1"

  cp "$APPLICATIONS_DIR/nmap.app/Contents/Resources/lib/libssl.3.dylib" "$APPLICATIONS_DIR/ncat.app/Contents/Resources/lib/" 2>/dev/null || true
  cp "$APPLICATIONS_DIR/nmap.app/Contents/Resources/lib/libcrypto.3.dylib" "$APPLICATIONS_DIR/ncat.app/Contents/Resources/lib/" 2>/dev/null || true
  ln -sf libssl.3.dylib "$APPLICATIONS_DIR/ncat.app/Contents/Resources/lib/libssl.dylib"
  ln -sf libcrypto.3.dylib "$APPLICATIONS_DIR/ncat.app/Contents/Resources/lib/libcrypto.dylib"

  for bin in "$APPLICATIONS_DIR/ncat.app/Contents/MacOS/ncat" "$APPLICATIONS_DIR/ncat.app/Contents/Resources/bin/ncat"; do
    for lib in libssl.3.dylib libcrypto.3.dylib; do
      old="$(otool -L "$bin" | awk -v lib="$lib" '$1 ~ lib {print $1; exit}')"
      if [ -n "$old" ]; then
        install_name_tool -change "$old" "@executable_path/../lib/$lib" "$bin" 2>/dev/null || true
      fi
    done
    install_name_tool -add_rpath "@executable_path/../Resources/lib" "$bin" 2>/dev/null || true
  done
else
  echo "warning: ncat/ncat not found"
fi

if [ -x "$ROOT_DIR/nping/nping" ]; then
  echo "Creating nping.app..."
  mkdir -p \
    "$APPLICATIONS_DIR/nping.app/Contents/MacOS" \
    "$APPLICATIONS_DIR/nping.app/Contents/Resources/bin" \
    "$APPLICATIONS_DIR/nping.app/Contents/Resources/lib" \
    "$APPLICATIONS_DIR/nping.app/Contents/Resources/share/man/man1"

  make_cli_plist "$APPLICATIONS_DIR/nping.app/Info.plist" "nping" "org.insecure.nmap.nping" "nping"
  cp "$ROOT_DIR/nping/nping" "$APPLICATIONS_DIR/nping.app/Contents/MacOS/nping"
  cp "$ROOT_DIR/nping/nping" "$APPLICATIONS_DIR/nping.app/Contents/Resources/bin/nping"
  chmod 755 "$APPLICATIONS_DIR/nping.app/Contents/MacOS/nping" "$APPLICATIONS_DIR/nping.app/Contents/Resources/bin/nping"
  copy_if_exists "$ROOT_DIR/nping/docs/nping.1" "$APPLICATIONS_DIR/nping.app/Contents/Resources/share/man/man1/nping.1"

  for lib in libssl.3.dylib libcrypto.3.dylib libpcap.A.dylib; do
    cp "$APPLICATIONS_DIR/nmap.app/Contents/Resources/lib/$lib" "$APPLICATIONS_DIR/nping.app/Contents/Resources/lib/" 2>/dev/null || true
  done
  ln -sf libssl.3.dylib "$APPLICATIONS_DIR/nping.app/Contents/Resources/lib/libssl.dylib"
  ln -sf libcrypto.3.dylib "$APPLICATIONS_DIR/nping.app/Contents/Resources/lib/libcrypto.dylib"
  ln -sf libpcap.A.dylib "$APPLICATIONS_DIR/nping.app/Contents/Resources/lib/libpcap.dylib"

  for bin in "$APPLICATIONS_DIR/nping.app/Contents/MacOS/nping" "$APPLICATIONS_DIR/nping.app/Contents/Resources/bin/nping"; do
    for lib in libssl.3.dylib libcrypto.3.dylib libpcap.A.dylib; do
      old="$(otool -L "$bin" | awk -v lib="$lib" '$1 ~ lib {print $1; exit}')"
      if [ -n "$old" ]; then
        install_name_tool -change "$old" "@executable_path/../lib/$lib" "$bin" 2>/dev/null || true
      fi
    done
    install_name_tool -add_rpath "@executable_path/../Resources/lib" "$bin" 2>/dev/null || true
  done
else
  echo "warning: nping/nping not found"
fi

if [ -f "$ROOT_DIR/ndiff/scripts/ndiff" ]; then
  cp "$ROOT_DIR/ndiff/scripts/ndiff" "$USR_LOCAL_DIR/bin/ndiff"
  chmod 755 "$USR_LOCAL_DIR/bin/ndiff"
elif [ -f "$ROOT_DIR/ndiff/ndiff.py" ]; then
  cp "$ROOT_DIR/ndiff/ndiff.py" "$USR_LOCAL_DIR/bin/ndiff"
  chmod 755 "$USR_LOCAL_DIR/bin/ndiff"
else
  echo "warning: ndiff executable not found"
fi

if [ -f "$ROOT_DIR/ndiff/ndiff.py" ]; then
  cp "$ROOT_DIR/ndiff/ndiff.py" "$USR_LOCAL_DIR/bin/ndiff.py"
  chmod 644 "$USR_LOCAL_DIR/bin/ndiff.py"
else
  echo "warning: ndiff module not found"
fi

copy_if_exists "$ROOT_DIR/ndiff/docs/ndiff.1" "$USR_LOCAL_DIR/share/man/man1/ndiff.1"

find "$REPLACEMENT_ROOT" -type f \( -name "*.dylib" -o -perm -111 \) -print0 | while IFS= read -r -d '' file; do
  codesign --force --sign - "$file" >/dev/null 2>&1 || true
done

echo
echo "Verifying replacement root..."
NMAPDIR="$APPLICATIONS_DIR/nmap.app/Contents/Resources/share/nmap" \
  "$APPLICATIONS_DIR/nmap.app/Contents/Resources/bin/nmap" --version

if [ -x "$APPLICATIONS_DIR/ncat.app/Contents/Resources/bin/ncat" ]; then
  "$APPLICATIONS_DIR/ncat.app/Contents/Resources/bin/ncat" --version
fi

if [ -x "$APPLICATIONS_DIR/nping.app/Contents/Resources/bin/nping" ]; then
  "$APPLICATIONS_DIR/nping.app/Contents/Resources/bin/nping" --version
fi

if [ -x "$USR_LOCAL_DIR/bin/ndiff" ]; then
  "$USR_LOCAL_DIR/bin/ndiff" -h >/dev/null
fi

echo
echo "Replacement root created:"
find "$REPLACEMENT_ROOT" -maxdepth 5 -print | sed "s#^$ROOT_DIR/##" | head -120
