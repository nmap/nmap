#!/bin/bash
# bash shebang because MSYS2/Styrene require Bash, not just /bin/sh
set -x
set -e

export MSYS2_ARG_CONV_EXCL=""
BUILDDIR=dist

: << '#MULTILINE_COMMENT'
# Setup environment
pacman -S --needed zip mingw-w64-x86_64-{python3,gcc,nsis,binutils,git}
pacman -S --needed mingw-w64-x86_64-python3-pip
git clone https://github.com/achadwick/styrene.git
git apply <<EOF
diff --git a/styrene/bundle.py b/styrene/bundle.py
index 7f5155e..e5c31d3 100644
--- a/styrene/bundle.py
+++ b/styrene/bundle.py
@@ -446,7 +446,7 @@ class NativeBundle:
             - (?P<version> [^-]+ - \d+ )
             - any
             [.]pkg[.]tar
-            (?: [.](?:gz|xz) )?
+            (?: [.](?:gz|xz|zst) )?
             $
         '''
         keyobj = functools.cmp_to_key(self._vercmp)
EOF
cd styrene
pip3 install .
#MULTILINE_COMMENT

# make the zenmap package
#makepkg-mingw -RdfL

# make the minimal msys2 environment
#styrene -p . -o "$BUILDDIR" styrene.cfg --no-exe --no-zip

PACKAGEDIR=$BUILDDIR/zenmap-w64
PYTHONLIB=$(ls -d $PACKAGEDIR/mingw64/lib/python3.*)
# Clean up unused Python modules
shopt -s globstar
rm -rf "$PYTHONLIB"/distutils/
rm -rf "$PYTHONLIB"/pydoc_data/
rm -rf "$PYTHONLIB"/ctypes/
rm -rf "$PYTHONLIB"/asyncio/
rm -rf "$PYTHONLIB"/multiprocessing/
rm -rf "$PYTHONLIB"/html/
rm -rf "$PYTHONLIB"/curses/
rm -rf "$PYTHONLIB"/ensurepip/
rm -rf "$PYTHONLIB"/idlelib/
rm -rf "$PYTHONLIB"/lib2to3/
rm -rf "$PYTHONLIB"/msilib/
rm -rf "$PYTHONLIB"/venv/
rm -rf "$PYTHONLIB"/xmlrpc/
rm -rf "$PYTHONLIB"/concurrent/
rm -rf "$PYTHONLIB"/json/
rm -rf "$PYTHONLIB"/test/
rm -rf "$PYTHONLIB"/tkinter/
rm -rf "$PYTHONLIB"/turtledemo/
rm -rf "$PYTHONLIB"/wsgiref/
rm -rf "$PYTHONLIB"/Tools/
rm -rf "$PYTHONLIB"/config-3.*/
rm -rf "$PYTHONLIB"/zoneinfo/
# Remove some of the larger unused items
rm "$PYTHONLIB"/_pydecimal.py
rm "$PYTHONLIB"/turtle.py
rm "$PYTHONLIB"/lib-dynload/_decimal.*.pyd
rm "$PYTHONLIB"/lib-dynload/_testcapi.*.pyd
rm -rf "$PYTHONLIB"/site-packages/**/*libxml2*

# Remove compiled bytecode, recompile in legacy locations, allowing for removal of source.
# See PEP-3147
find "$PYTHONLIB"  -depth \( -name 'zenmap*' -o -name 'radialnet' \) -prune -o -name __pycache__ -exec rm -rf '{}' \;
# Exit code not reliable
"$BUILDDIR/zenmap-w64/mingw64/bin/python.exe" -m compileall -b -x 'zenmapGUI|zenmapCore|radialnet' "$PYTHONLIB" || true

# Remove source if compiled is available, except for Zenmap itself:
find "$PYTHONLIB" \( -name 'zenmap*' -o -name 'radialnet' \) -prune -o \( -name '*.pyc' -print \) | while read pyc; do
pysrc="${pyc%.pyc}.py"
if [ -f "$pysrc" ]; then
	rm "$pysrc"
fi
done

# Now compile Zenmap using default (not legacy) location.
# If we had used legacy location, python.exe tries to write out the PEP-3147
# location anyway when source is available.
"$BUILDDIR/zenmap-w64/mingw64/bin/python.exe" -m compileall "$PYTHONLIB"/site-packages || true

# Remove some of the larger unused items
rm "$PACKAGEDIR"/mingw64/bin/libGLESv*.dll
rm "$PACKAGEDIR"/mingw64/bin/libEGL.dll
# strip binaries
find "$PACKAGEDIR" \( -name '*.exe' -o -name '*.dll' \) -exec strip -g '{}' \;

# Remove pacman database
rm -rf "$PACKAGEDIR/var/lib/pacman/"

# fake a new install script for what we removed:
mkdir -p "$PACKAGEDIR/var/lib/pacman/local/zenmap-fake-pkg/"
cat >"$PACKAGEDIR/var/lib/pacman/local/zenmap-fake-pkg/install" <<EOF
post_install() {
    mingw64/bin/gtk-update-icon-cache -q -t -f mingw64/share/icons/hicolor
}
EOF
