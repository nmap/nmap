#!/bin/bash
# bash shebang because MSYS2/Styrene require Bash, not just /bin/sh
set -x
set -e

export MSYS2_ARG_CONV_EXCL=""
BUILDDIR=dist

: << '#MULTILINE_COMMENT'
# Setup environment
pacman -S --needed git zip mingw-w64-x86_64-{python3,gcc,nsis,binutils}
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

PYTHON_VER=3.11
PACKAGEDIR=$BUILDDIR/zenmap-w64/mingw64
PYTHON_SUBDIR=lib/python$PYTHON_VER
PYTHONLIB=$PACKAGEDIR/$PYTHON_SUBDIR

# Remove compiled bytecode, recompile in legacy locations, allowing for removal of source.
# See PEP-3147
find "$PYTHONLIB"  -depth \( -name 'zenmap*' -o -name 'radialnet' \) -prune -o -name __pycache__ -exec rm -rf '{}' \;
# Exit code not reliable
pushd "$PACKAGEDIR/bin"
python -m compileall -b -x 'zenmapGUI|zenmapCore|radialnet' "../$PYTHON_SUBDIR" #|| true
popd

# Remove source if compiled is available, except for Zenmap itself:
find "$PYTHONLIB" \( -name 'zenmap*' -o -name 'radialnet' \) -prune -o \( -name '*.pyc' -print \) | while read pyc; do
rm -f "${pyc%.pyc}.py"
done

# Now compile Zenmap using default (not legacy) location.
# If we had used legacy location, python.exe tries to write out the PEP-3147
# location anyway when source is available.
pushd "$PACKAGEDIR/bin"
python -m compileall "../$PYTHON_SUBDIR"/site-packages #|| true
popd

# Remove some of the larger unused items
rm -f "$PACKAGEDIR"/bin/win7appid.exe

# strip binaries
find "$PACKAGEDIR" \( -name '*.exe' -o -name '*.dll' -o -name '*.pyd' \) -exec strip -g '{}' \;

# Create cache files as needed
cd "$PACKAGEDIR"
export GDK_PIXBUF_MODULEDIR=$(ls -d lib/gdk-pixbuf-2.0/2.*/loaders)
gdk-pixbuf-query-loaders > "$GDK_PIXBUF_MODULEDIR".cache
gtk-update-icon-cache share/icons/hicolor

