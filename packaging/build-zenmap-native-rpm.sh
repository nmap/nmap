#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-$(python3 "${ROOT}/packaging/nmap-version.py")}"

BUILD_DIR="${BUILD_DIR:-${ROOT}/packaging/rpm-build}"
SPEC="${BUILD_DIR}/zenmap-native.spec"

mkdir -p "${BUILD_DIR}/SOURCES" "${BUILD_DIR}/BUILD" "${BUILD_DIR}/RPMS" "${BUILD_DIR}/SRPMS"

tar -C "${ROOT}" \
  --exclude=.git \
  --exclude=.xcode-build \
  --exclude=packaging/rpm-build \
  -czf "${BUILD_DIR}/SOURCES/nmap-${VERSION}.tar.gz" \
  --transform "s,^,nmap-${VERSION}/," .

sed "s/@VERSION@/${VERSION}/g" "${ROOT}/zenmap-native.spec.in" > "${SPEC}"

rpmbuild -ba "${SPEC}" \
  --define "_sourcedir ${BUILD_DIR}/SOURCES" \
  --define "_builddir ${BUILD_DIR}/BUILD" \
  --define "_rpmdir ${BUILD_DIR}/RPMS" \
  --define "_srcrpmdir ${BUILD_DIR}/SRPMS" \
  --define "_specdir ${BUILD_DIR}"

echo "RPM build complete. Artifacts are under ${BUILD_DIR}/RPMS"
