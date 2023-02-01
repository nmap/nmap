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
makepkg-mingw -RdfL

# make the minimal msys2 environment
styrene -p . -o "$BUILDDIR" styrene.cfg --no-exe --no-zip

# Clean up unused Python modules
rm -rf "$BUILDDIR/**/*.opt-?.pyc"
rm -rf "$BUILDDIR/distutils/"
rm -rf "$BUILDDIR/pydoc_data/"
rm -rf "$BUILDDIR/ctypes/"
rm -rf "$BUILDDIR/asyncio/"
rm -rf "$BUILDDIR/multiprocessing/"
rm -rf "$BUILDDIR/html/"
rm -rf "$BUILDDIR/msilib/"
rm -rf "$BUILDDIR/venv/"
rm -rf "$BUILDDIR/xmlrpc/"
rm -rf "$BUILDDIR/concurrent/"
rm -rf "$BUILDDIR/json/"
rm -rf "$BUILDDIR/config-3.*/"
rm -rf "$BUILDDIR/zoneinfo/"

# Remove pacman database
rm -rf var/lib/pacman/

# fake a new install script for what we removed:
mkdir -p var/lib/pacman/local/zenmap-fake-pkg/
cat >var/lib/pacman/local/zenmap-fake-pkg/install <<EOF
post_install() {
    mingw64/bin/gtk-update-icon-cache -q -t -f mingw64/share/icons/hicolor
    mingw64/bin/gtk-update-icon-cache -q -t -f mingw64/share/icons/Adwaita
}
EOF
