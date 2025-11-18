#!/bin/bash
# Setup environment for building Zenmap installer on Windows
# Install MSYS2 and run this in the MinGW64 shell: 
set -x
set -e
pkg_prefix=mingw-w64-x86_64-
pacman -S --needed git zip ${pkg_prefix}{python,gcc,nsis,binutils}
pacman -S --needed ${pkg_prefix}python-gobject ${pkg_prefix}gtk3 msys2-runtime
pacman -S --needed mingw-w64-x86_64-python3-pip
git clone https://github.com/achadwick/styrene.git
cd styrene
git apply <<'EOF'
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
diff --git a/styrene/cmdline.py b/styrene/cmdline.py
index 92eecd4..5e04701 100644
--- a/styrene/cmdline.py
+++ b/styrene/cmdline.py
@@ -246,7 +246,7 @@ def main():
     # Process bundles
     for spec_file in args:
         try:
-            spec = configparser.SafeConfigParser()
+            spec = configparser.RawConfigParser()
             spec.read(spec_file, encoding="utf-8")
         except Exception:
             logger.exception(
EOF
pip3 install .
