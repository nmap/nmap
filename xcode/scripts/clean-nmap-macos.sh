#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"

echo "Cleaning Xcode/Nmap build products..."

if [ -f Makefile ]; then
  make clean || true
fi

for dir in \
  nbase \
  nsock/src \
  libnetutil \
  liblinear \
  libpcap \
  libpcre \
  liblua \
  libdnet-stripped \
  ncat \
  nping
do
  if [ -f "$dir/Makefile" ]; then
    (cd "$dir" && make clean) || true
  fi
done

rm -f nmap ncat/ncat nping/nping

find . -maxdepth 1 -type f \( -name '*.o' -o -name '*.d' -o -name '*.gcno' -o -name '*.gcda' \) -delete
find . -path '*/.deps/*' -type f -delete 2>/dev/null || true

rm -f makefile.dep nping/makefile.dep ncat/makefile.dep

find nping ncat nbase nsock libnetutil liblinear libpcap libpcre liblua libdnet-stripped \
  -type f \( -name '*.o' -o -name '*.d' -o -name '*.lo' -o -name '*.la' -o -name '*.gcno' -o -name '*.gcda' \) -delete 2>/dev/null || true

rm -f \
  nbase/libnbase.a \
  nsock/src/libnsock.a \
  libnetutil/libnetutil.a \
  liblinear/liblinear.a \
  liblua/liblua.a \
  libpcap/libpcap.a

rm -rf \
  libpcre/.libs \
  libdnet-stripped/src/.libs \
  .xcode-products \
  dist

if [ -n "${BUILD_DIR:-}" ]; then
  rm -rf "$BUILD_DIR" 2>/dev/null || true
fi

echo "Clean complete."
