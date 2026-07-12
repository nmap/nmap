#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROJECT="${REPO_ROOT}/NmapMac.xcodeproj"
SCHEME="${SCHEME:-NmapNative}"
CONFIGURATION="${CONFIGURATION:-Debug}"
DERIVED_DATA="${DERIVED_DATA:-${REPO_ROOT}/.xcode-build}"

echo "Building macOS ${SCHEME} (${CONFIGURATION})..."
xcodebuild \
  -project "${PROJECT}" \
  -scheme "${SCHEME}" \
  -configuration "${CONFIGURATION}" \
  -destination 'platform=macOS' \
  -derivedDataPath "${DERIVED_DATA}" \
  build

APP_PATH="${DERIVED_DATA}/Build/Products/${CONFIGURATION}/Zenmap.app"
NMAP_PATH="${APP_PATH}/Contents/Resources/bin/nmap"

if [[ ! -d "${APP_PATH}" ]]; then
  echo "Expected app bundle not found: ${APP_PATH}" >&2
  exit 1
fi

if [[ ! -x "${NMAP_PATH}" ]]; then
  echo "Bundled nmap not found: ${NMAP_PATH}" >&2
  exit 1
fi

echo "Verifying bundled nmap..."
"${NMAP_PATH}" --version | head -2

echo "Verifying app bundle metadata..."
/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "${APP_PATH}/Contents/Info.plist"
/usr/bin/codesign --verify --deep --strict --verbose=0 "${APP_PATH}"

echo "macOS native build verification passed."
echo "App: ${APP_PATH}"
