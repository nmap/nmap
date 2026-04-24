#!/bin/sh
set -x
set -e

if [ "x$1" == "x" ]; then
  echo "Need a name"
  exit 1
fi
package=$1

if [ "x$2" == "x" ]; then
  echo "Need a JHBUILD_PREFIX"
  exit 1
fi
JHBUILD_PREFIX=$2

bundle=$package-root/$package.app
bundle_contents="$bundle"/Contents
bundle_res="$bundle_contents"/Resources
bundle_lib="$bundle_res"/lib
bundle_bin="$bundle_res"/bin
bundle_data="$bundle_res"/share

function do_lib() {
  libname=$1
  grep '^lib/.*\.dylib$' "$JHBUILD_PREFIX/_jhbuild/manifests/$libname" >/tmp/$libname.libs
  rsync -avu --files-from /tmp/$libname.libs "$JHBUILD_PREFIX/" "$bundle_res"
}

ESCAPED_PREFIX=$(echo "$JHBUILD_PREFIX" | sed 's/\([\/\\.]\)/\\\1/g')
function run_install_name_tool() {
  bin=$1
  otool -L "$bin" | awk "/$ESCAPED_PREFIX/{print \$1}" | while read dep; do
    install_name_tool -change $dep $(echo $dep | sed "s/$ESCAPED_PREFIX\/lib/@rpath/") "$bin"
  done
  install_name_tool -add_rpath "@executable_path/../lib" "$bin" || true
}

function do_jhbuild_app() {
  do_lib openssl
  cp launcher.sh "$bundle_contents"/MacOS/$package
  rsync -avu --files-from "$JHBUILD_PREFIX/_jhbuild/manifests/$package" "$JHBUILD_PREFIX/" "$bundle_res"
}

mkdir -p "$bundle_res"
mkdir -p "$bundle_contents"/MacOS

APP_WEB_SITE=https://nmap.org/
BUNDLE_ID=org.insecure.nmap
case "$package" in
  nmap)
    do_jhbuild_app
    do_lib libpcap
    do_lib libpcre2
    rm "$bundle_lib"/libpcre2-{16,32,posix}.*
    do_lib libssh2
    do_lib zlib
    run_install_name_tool "$bundle_bin"/nmap
    ;;
  ncat)
    do_jhbuild_app
    run_install_name_tool "$bundle_bin"/ncat
    APP_WEB_SITE="${APP_WEB_SITE}ncat/"
    BUNDLE_ID="${BUNDLE_ID}.ncat"
    ;;
  nping)
    do_jhbuild_app
    do_lib libpcap
    run_install_name_tool "$bundle_bin"/nping
    APP_WEB_SITE="${APP_WEB_SITE}nping/"
    BUNDLE_ID="${BUNDLE_ID}.nping"
    ;;
  ndiff)
    APP_WEB_SITE="${APP_WEB_SITE}ndiff/"
    BUNDLE_ID="${BUNDLE_ID}.ndiff"
    ln -sf '../Resources/ndiff.py' "$bundle_contents"/MacOS/ndiff
    cp ../ndiff/ndiff.py "$bundle_res/"
    cp ../ndiff/docs/ndiff.1 "$bundle_res/"
    ;;
  *)
    echo "Invalid package $package"
    exit 2
    ;;
esac

echo "Filling out Info.plist"
export APP_WEB_SITE
export BUNDLE_ID
export package
python3 - "Info.plist.in" >"$bundle/Info.plist" <<'EOF'
import sys
from os import environ
from string import Template
with open(sys.argv[1],"r",encoding="utf-8") as f:
  sys.stdout.write(Template(f.read()).substitute(
    BUNDLE_IDENTIFIER=environ["BUNDLE_ID"],
    BUNDLE_NAME=environ["package"].title(),
    BUNDLE_EXE=environ["package"],
    OSX_MIN_VERSION=environ["OSX_MIN_VERSION"],
    VERSION=environ["NMAP_VERSION"],
    APP_WEB_SITE=environ["APP_WEB_SITE"],
    APP_COPYRIGHT="Copyright 1996-2026 Nmap Software LLC",
    EXTRA_DICT_CONTENT=""
    ))
EOF

find "$bundle_lib" -type f -name '*.dylib' | while read so; do
  run_install_name_tool "$so"
  # This isn't truly necessary, but it allows us to do a simpler check for problems later.
  dep=$(basename "$so")
  install_name_tool -id "@executable_path/../lib/$dep" "$so"
done
