#!/bin/bash -e
set -x

test "x$UNDER_JHBUILD" = "x" && exit 1

# make-bundle.sh
APP_NAME=Zenmap
ZENMAP_DIST_DIR=$PWD/dist
ZENMAP_BUILD_DIR=$PWD/build

export ZENMAP_DIST_DIR
export ZENMAP_BUILD_DIR

BASE=$ZENMAP_DIST_DIR/$APP_NAME.app/Contents
SCRIPT_DIR=`dirname "$0"`

echo "Running $0."

echo "Removing old build."
rm -rf "$ZENMAP_DIST_DIR" "$ZENMAP_BUILD_DIR"

echo "Building python-launcher"
$CC $CPPFLAGS $CFLAGS $LDFLAGS -L$PREFIX/lib `python3-config --cflags --ldflags --embed` \
	    -o $PREFIX/bin/zenmap-launcher \
	    ~/gtk-mac-bundler/examples/python-launcher.c

echo "Installing Zenmap to local system"
python3 setup.py install vanilla --prefix "$PREFIX"

echo "Generating dependencies"
# Have to run this with ~/gtk/inst/python3 or deps have wrong paths
export XDG_DATA_DIRS=$PREFIX/share
export DYLD_LIBRARY_PATH=$PREFIX/lib
export LD_LIBRARY_PATH=$PREFIX/lib
export GTK_DATA_PREFIX=$PREFIX
export GTK_EXE_PREFIX=$PREFIX
export GTK_PATH=$PREFIX
export PANGO_RC_FILE=$PREFIX/etc/pango/pangorc
export PANGO_SYSCONFDIR=$PREFIX/etc
export PANGO_LIBDIR=$PREFIX/lib
export GDK_PIXBUF_MODULE_FILE=$PREFIX/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache
export GTK_IM_MODULE_FILE=$PREFIX/etc/gtk-3.0/gtk.immodules
export GI_TYPELIB_PATH=$PREFIX/lib/girepository-1.0

python3 "$SCRIPT_DIR/../utils/get_deps.py" "$SCRIPT_DIR/pyreqs.xml"
# gtk-mac-bundler (xml.dom.minidom) doesn't expand external entities
xmllint --format --noent "$SCRIPT_DIR/zenmap.bundle" > "$SCRIPT_DIR/tmp.bundle"

echo "Building bundle"
gtk-mac-bundler "$SCRIPT_DIR/tmp.bundle"

echo "Removing unneeded items"
# GIR files not needed, only typelib
rm -rf $BASE/Resources/share/gir-1.0/

echo "Creating caches"
pushd "$BASE/Resources"
export GDK_PIXBUF_MODULEDIR=$(ls - lib/gdk-pixbuf-2.0/2.*/loaders)
gdk-pixbuf-query-loaders > "$GDK_PIXBUF_MODULEDIR".cache
gtk-update-icon-cache share/icons/hicolor
popd

# echo "Compiling Python to bytecode"
PYTHONLIB=$(ls -d $BASE/Resources/lib/python3.*)
# Remove compiled bytecode, recompile in legacy locations, allowing for removal of source.
# See PEP-3147
find "$PYTHONLIB"  -depth \( -name 'zenmap*' -o -name 'radialnet' \) -prune -o -name __pycache__ -exec rm -rf '{}' \;
python -m compileall -b -x 'zenmapGUI|zenmapCore|radialnet' "$PYTHONLIB"

# Remove source if compiled is available, except for Zenmap itself:
find "$PYTHONLIB" \( -name 'zenmap*' -o -name 'radialnet' \) -prune -o \( -name '*.pyc' -print \) | while read pyc; do
rm -f "${pyc%.pyc}.py"
done

# Now compile Zenmap using default (not legacy) location.
# If we had used legacy location, python.exe tries to write out the PEP-3147
# location anyway when source is available.
python -m compileall "$PYTHONLIB"/site-packages #|| true
echo "Stripping unoptimized Python libraries"

echo "Building using distutils"
python3 setup.py build --executable "/usr/bin/env python3"
python3 setup.py install vanilla --prefix "$BASE/Resources"

echo "Renaming main Zenmap executable."
mv $BASE/MacOS/$APP_NAME $BASE/MacOS/zenmap.bin
# This is a dummy script, so we'll clean it up:
#rm $BASE/MacOS/$APP_NAME-bin

echo "Compiling and installing authorization wrapper."
echo $CC $CPPFLAGS $OBJCFLAGS $LDFLAGS -v "$SCRIPT_DIR/zenmap_auth.m" -lobjc -framework Foundation -o "$BASE/MacOS/$APP_NAME"
$CC $CPPFLAGS $OBJCFLAGS $LDFLAGS -v "$SCRIPT_DIR/zenmap_auth.m" -lobjc -framework Foundation -o "$BASE/MacOS/$APP_NAME"

echo "Filling out Info.plist"
python3 - "$SCRIPT_DIR/Info.plist" >"$BASE/Info.plist" <<'EOF'
import sys
from string import Template
from zenmapCore.Version import *
from zenmapCore.Name import *
with open(sys.argv[1],"r") as f:
  sys.stdout.write(Template(f.read()).substitute(
    VERSION=VERSION,
    APP_WEB_SITE=APP_WEB_SITE,
    APP_COPYRIGHT=APP_COPYRIGHT
    ))
EOF
