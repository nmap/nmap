#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

DIST_DIR="$ROOT_DIR/dist"
REPLACEMENT_ROOT="$DIST_DIR/replacement-root"
APPLICATIONS_DIR="$REPLACEMENT_ROOT/Applications"
USR_LOCAL_DIR="$REPLACEMENT_ROOT/usr/local"
PKG_WORK_DIR="$DIST_DIR/pkg-work"
PKG_OUT_DIR="$DIST_DIR/pkg"
IDENTIFIER_PREFIX="${IDENTIFIER_PREFIX:-org.insecure.nmap}"
VERSION="${VERSION:-7.99}"

NMAP_PKG="$PKG_OUT_DIR/Nmap.pkg"
NCAT_PKG="$PKG_OUT_DIR/Ncat.pkg"
NPING_PKG="$PKG_OUT_DIR/Nping.pkg"
NDIFF_PKG="$PKG_OUT_DIR/Ndiff.pkg"
ZENMAP_PKG="$PKG_OUT_DIR/Zenmap.pkg"
COMPLETE_PKG="$PKG_OUT_DIR/NmapComplete.pkg"

require_replacement_root() {
  if [ ! -d "$REPLACEMENT_ROOT" ]; then
    echo "Missing $REPLACEMENT_ROOT"
    echo "Running: bash macosx/stage-nmap-replacement-root-macos.sh"
    bash macosx/stage-nmap-replacement-root-macos.sh
  fi

  if [ ! -d "$REPLACEMENT_ROOT" ]; then
    echo "error: replacement root was not created" >&2
    exit 1
  fi
}

copy_gui_as_zenmap() {
  local gui_source="$DIST_DIR/Zenmap.app"
  local zenmap_destination="$APPLICATIONS_DIR/Zenmap.app"

  if [ ! -d "$gui_source" ]; then
    echo "Missing $gui_source"
    echo "Running: bash macosx/release-zenmap-macos.sh"
    bash macosx/release-zenmap-macos.sh
  fi

  if [ ! -d "$gui_source" ]; then
    echo "error: required GUI app was not created: $gui_source" >&2
    exit 1
  fi

  rm -rf "$zenmap_destination"
  cp -R "$gui_source" "$zenmap_destination"

  if [ -f "$zenmap_destination/Contents/Info.plist" ]; then
    /usr/libexec/PlistBuddy -c "Set :CFBundleName Zenmap" "$zenmap_destination/Contents/Info.plist" 2>/dev/null || true
    /usr/libexec/PlistBuddy -c "Set :CFBundleDisplayName Zenmap" "$zenmap_destination/Contents/Info.plist" 2>/dev/null || \
      /usr/libexec/PlistBuddy -c "Add :CFBundleDisplayName string Zenmap" "$zenmap_destination/Contents/Info.plist"
    /usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier org.insecure.nmap.zenmap" "$zenmap_destination/Contents/Info.plist" 2>/dev/null || true
  fi

  codesign --force --deep --sign - "$zenmap_destination" >/dev/null 2>&1 || true
}

make_component_root() {
  local source_path="$1"
  local destination_root="$2"
  local relative_path="$3"

  mkdir -p "$destination_root/$(dirname "$relative_path")"

  # Use ditto without resource forks or extended attributes so pkgbuild does not
  # synthesize AppleDouble files like ._nselib and ._scripts.
  ditto --norsrc --noextattr "$source_path" "$destination_root/$relative_path"

  chmod -R u+rwX "$destination_root"
  xattr -cr "$destination_root" 2>/dev/null || true
  xattr -dr com.apple.macl "$destination_root" 2>/dev/null || true
  dot_clean -m "$destination_root" 2>/dev/null || true
  find "$destination_root" -name '._*' -delete 2>/dev/null || true
}

require_replacement_root
copy_gui_as_zenmap

clean_packaging_metadata() {
  local root="$1"

  if [ -e "$root" ]; then
    xattr -cr "$root" 2>/dev/null || true
    dot_clean -m "$root" 2>/dev/null || true
    find "$root" -name '._*' -delete 2>/dev/null || true
  fi
}

rm -rf "$PKG_WORK_DIR" "$PKG_OUT_DIR"
mkdir -p "$PKG_WORK_DIR" "$PKG_OUT_DIR"

cat > "$PKG_WORK_DIR/NoBundleComponents.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array/>
</plist>
PLIST

rm -rf "$PKG_WORK_DIR/nmap-root" "$PKG_WORK_DIR/ncat-root" "$PKG_WORK_DIR/nping-root" "$PKG_WORK_DIR/ndiff-root" "$PKG_WORK_DIR/zenmap-root"

make_component_root "$APPLICATIONS_DIR/nmap.app" "$PKG_WORK_DIR/nmap-root" "Applications/nmap.app"
make_component_root "$USR_LOCAL_DIR/bin/nmap" "$PKG_WORK_DIR/nmap-root" "usr/local/bin/nmap"

make_component_root "$APPLICATIONS_DIR/ncat.app" "$PKG_WORK_DIR/ncat-root" "Applications/ncat.app"
make_component_root "$USR_LOCAL_DIR/bin/ncat" "$PKG_WORK_DIR/ncat-root" "usr/local/bin/ncat"

make_component_root "$APPLICATIONS_DIR/nping.app" "$PKG_WORK_DIR/nping-root" "Applications/nping.app"
make_component_root "$USR_LOCAL_DIR/bin/nping" "$PKG_WORK_DIR/nping-root" "usr/local/bin/nping"

make_component_root "$USR_LOCAL_DIR/bin/ndiff" "$PKG_WORK_DIR/ndiff-root" "usr/local/bin/ndiff"
make_component_root "$USR_LOCAL_DIR/bin/ndiff.py" "$PKG_WORK_DIR/ndiff-root" "usr/local/bin/ndiff.py"

make_component_root "$APPLICATIONS_DIR/Zenmap.app" "$PKG_WORK_DIR/zenmap-root" "Applications/Zenmap.app"

echo "Cleaning packaging metadata..."
xattr -cr "$REPLACEMENT_ROOT" 2>/dev/null || true
find "$REPLACEMENT_ROOT" -name '._*' -delete

clean_packaging_metadata "$PKG_WORK_DIR/nmap-root"
clean_packaging_metadata "$PKG_WORK_DIR/ncat-root"
clean_packaging_metadata "$PKG_WORK_DIR/nping-root"
clean_packaging_metadata "$PKG_WORK_DIR/ndiff-root"
clean_packaging_metadata "$PKG_WORK_DIR/zenmap-root"

pkgbuild \
  --component-plist "$PKG_WORK_DIR/NoBundleComponents.plist" \
  --root "$PKG_WORK_DIR/nmap-root" \
  --identifier "$IDENTIFIER_PREFIX" \
  --version "$VERSION" \
  --install-location / \
  "$NMAP_PKG"

pkgbuild \
  --component-plist "$PKG_WORK_DIR/NoBundleComponents.plist" \
  --root "$PKG_WORK_DIR/ncat-root" \
  --identifier "$IDENTIFIER_PREFIX.ncat" \
  --version "$VERSION" \
  --install-location / \
  "$NCAT_PKG"

pkgbuild \
  --component-plist "$PKG_WORK_DIR/NoBundleComponents.plist" \
  --root "$PKG_WORK_DIR/nping-root" \
  --identifier "$IDENTIFIER_PREFIX.nping" \
  --version "$VERSION" \
  --install-location / \
  "$NPING_PKG"

pkgbuild \
  --component-plist "$PKG_WORK_DIR/NoBundleComponents.plist" \
  --root "$PKG_WORK_DIR/ndiff-root" \
  --identifier "$IDENTIFIER_PREFIX.ndiff" \
  --version "$VERSION" \
  --install-location / \
  "$NDIFF_PKG"

pkgbuild \
  --component-plist "$PKG_WORK_DIR/NoBundleComponents.plist" \
  --root "$PKG_WORK_DIR/zenmap-root" \
  --identifier "$IDENTIFIER_PREFIX.zenmap" \
  --version "$VERSION" \
  --install-location / \
  "$ZENMAP_PKG"

cat > "$PKG_WORK_DIR/Distribution.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
  <title>Nmap 7.99 for macOS</title>
  <organization>org.insecure</organization>
  <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
  <options customize="always" require-scripts="false" rootVolumeOnly="true"/>

  <choices-outline>
    <line choice="nmap"/>
    <line choice="ncat"/>
    <line choice="nping"/>
    <line choice="ndiff"/>
    <line choice="zenmap"/>
  </choices-outline>

  <choice id="nmap" title="Nmap" description="Install the native macOS Nmap command-line bundle at /Applications/nmap.app." selected="true" enabled="true" visible="true">
    <pkg-ref id="$IDENTIFIER_PREFIX"/>
  </choice>

  <choice id="ncat" title="Ncat" description="Install the native macOS Ncat command-line bundle at /Applications/ncat.app." selected="true" enabled="true" visible="true">
    <pkg-ref id="$IDENTIFIER_PREFIX.ncat"/>
  </choice>

  <choice id="nping" title="Nping" description="Install the native macOS Nping command-line bundle at /Applications/nping.app." selected="true" enabled="true" visible="true">
    <pkg-ref id="$IDENTIFIER_PREFIX.nping"/>
  </choice>

  <choice id="ndiff" title="Ndiff" description="Install Ndiff into /usr/local/bin and /usr/local/share/man." selected="true" enabled="true" visible="true">
    <pkg-ref id="$IDENTIFIER_PREFIX.ndiff"/>
  </choice>

  <choice id="zenmap" title="Zenmap" description="Install the native SwiftUI macOS frontend as /Applications/Zenmap.app." selected="true" enabled="true" visible="true">
    <pkg-ref id="$IDENTIFIER_PREFIX.zenmap"/>
  </choice>

  <pkg-ref id="$IDENTIFIER_PREFIX" version="$VERSION" onConclusion="none">Nmap.pkg</pkg-ref>
  <pkg-ref id="$IDENTIFIER_PREFIX.ncat" version="$VERSION" onConclusion="none">Ncat.pkg</pkg-ref>
  <pkg-ref id="$IDENTIFIER_PREFIX.nping" version="$VERSION" onConclusion="none">Nping.pkg</pkg-ref>
  <pkg-ref id="$IDENTIFIER_PREFIX.ndiff" version="$VERSION" onConclusion="none">Ndiff.pkg</pkg-ref>
  <pkg-ref id="$IDENTIFIER_PREFIX.zenmap" version="$VERSION" onConclusion="none">Zenmap.pkg</pkg-ref>
</installer-gui-script>
XML

CLI_PKG="$PKG_OUT_DIR/NmapCLI.pkg"
GUI_PKG="$PKG_OUT_DIR/ZenmapOnly.pkg"

productbuild \
  --package "$PKG_OUT_DIR/Nmap.pkg" \
  --package "$PKG_OUT_DIR/Ncat.pkg" \
  --package "$PKG_OUT_DIR/Nping.pkg" \
  --package "$PKG_OUT_DIR/Ndiff.pkg" \
  "$CLI_PKG"

productbuild \
  --package "$PKG_OUT_DIR/Zenmap.pkg" \
  "$GUI_PKG"

productbuild \
  --package "$PKG_OUT_DIR/Nmap.pkg" \
  --package "$PKG_OUT_DIR/Ncat.pkg" \
  --package "$PKG_OUT_DIR/Nping.pkg" \
  --package "$PKG_OUT_DIR/Ndiff.pkg" \
  --package "$PKG_OUT_DIR/Zenmap.pkg" \
  "$COMPLETE_PKG"

echo
echo "Installer packages created:"
ls -lh \
  "$PKG_OUT_DIR/Nmap.pkg" \
  "$PKG_OUT_DIR/Ncat.pkg" \
  "$PKG_OUT_DIR/Nping.pkg" \
  "$PKG_OUT_DIR/Ndiff.pkg" \
  "$PKG_OUT_DIR/Zenmap.pkg" \
  "$PKG_OUT_DIR/NmapCLI.pkg" \
  "$PKG_OUT_DIR/ZenmapOnly.pkg" \
  "$PKG_OUT_DIR/NmapComplete.pkg"

echo
echo "Install choices:"
echo "  NmapCLI.pkg       command-line tools only"
echo "  ZenmapOnly.pkg    Zenmap GUI only"
echo "  NmapComplete.pkg  command-line tools plus Zenmap"

echo
echo "Inspect component packages with:"
echo "  pkgutil --payload-files '$PKG_OUT_DIR/Nmap.pkg' | head -80"
echo "  pkgutil --payload-files '$PKG_OUT_DIR/Ncat.pkg' | head -80"
echo "  pkgutil --payload-files '$PKG_OUT_DIR/Nping.pkg' | head -80"
echo "  pkgutil --payload-files '$PKG_OUT_DIR/Ndiff.pkg' | head -80"
echo "  pkgutil --payload-files '$PKG_OUT_DIR/Zenmap.pkg' | head -80"

echo
echo "Inspect product packages with:"
echo "  pkgutil --expand '$PKG_OUT_DIR/NmapCLI.pkg' /tmp/NmapCLI-expanded"
echo "  pkgutil --expand '$PKG_OUT_DIR/ZenmapOnly.pkg' /tmp/ZenmapOnly-expanded"
echo "  pkgutil --expand '$PKG_OUT_DIR/NmapComplete.pkg' /tmp/NmapComplete-expanded"
