#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-$(python3 "${ROOT}/packaging/nmap-version.py")}"

BUILD_DIR="${BUILD_DIR:-${ROOT}/packaging/arch-build}"
PKGDIR="${BUILD_DIR}/zenmap-native-${VERSION}"

mkdir -p "${BUILD_DIR}"
rm -rf "${PKGDIR}"
mkdir -p "${PKGDIR}"

tar -C "${ROOT}" \
  --exclude=.git \
  --exclude=.xcode-build \
  -czf "${PKGDIR}/nmap-${VERSION}.tar.gz" \
  --transform "s,^,nmap-${VERSION}/," .

cp "${ROOT}/packaging/arch/PKGBUILD" "${PKGDIR}/PKGBUILD"
cd "${PKGDIR}"
makepkg -sf --noconfirm

echo "Arch package build complete in ${PKGDIR}"
