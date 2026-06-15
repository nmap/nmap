#!/bin/sh
# Bundle Nmap runtime files into an app-local layout for NmapGUI.app.

set -e

ROOT="${PROJECT_DIR:-$SRCROOT}"
RES="${TARGET_BUILD_DIR}/${UNLOCALIZED_RESOURCES_FOLDER_PATH}"
BIN="$RES/bin"
SHARE="$RES/share/nmap"

echo "Bundling Nmap runtime files"
echo "ROOT=$ROOT"
echo "RES=$RES"
echo "BIN=$BIN"
echo "SHARE=$SHARE"

mkdir -p "$BIN" "$SHARE"

if [ ! -x "$ROOT/nmap" ]; then
  echo "error: Built nmap binary not found at $ROOT/nmap"
  echo "Build the NmapCLI target first, or run make from the repo root."
  exit 1
fi

cp "$ROOT/nmap" "$BIN/nmap"
chmod +x "$BIN/nmap"

for f in \
  nmap-services \
  nmap-protocols \
  nmap-rpc \
  nmap-mac-prefixes \
  nmap-os-db \
  nmap-service-probes \
  nse_main.lua
do
  if [ -e "$ROOT/$f" ]; then
    cp "$ROOT/$f" "$SHARE/"
  else
    echo "warning: optional Nmap data file missing: $f"
  fi
done

if [ -f "$ROOT/docs/nmap.dtd" ]; then
  cp "$ROOT/docs/nmap.dtd" "$SHARE/nmap.dtd"
elif [ -f "$ROOT/nmap.dtd" ]; then
  cp "$ROOT/nmap.dtd" "$SHARE/nmap.dtd"
else
  echo "warning: optional Nmap data file missing: nmap.dtd"
fi

if [ -d "$ROOT/scripts" ]; then
  rm -rf "$SHARE/scripts"
  cp -R "$ROOT/scripts" "$SHARE/scripts"
else
  echo "warning: scripts directory missing"
fi

if [ -d "$ROOT/nselib" ]; then
  rm -rf "$SHARE/nselib"
  cp -R "$ROOT/nselib" "$SHARE/nselib"
else
  echo "warning: nselib directory missing"
fi

# Remove older flat bundle layout from previous builds.
rm -f "$RES/nmap"
rm -f "$RES"/nmap-services "$RES"/nmap-protocols "$RES"/nmap-rpc
rm -f "$RES"/nmap-mac-prefixes "$RES"/nmap-os-db "$RES"/nmap-service-probes
rm -f "$RES"/nse_main.lua "$RES"/nmap.dtd
rm -rf "$RES/scripts" "$RES/nselib"

echo "Bundled nmap:"
NMAPDIR="$SHARE" "$BIN/nmap" --version
