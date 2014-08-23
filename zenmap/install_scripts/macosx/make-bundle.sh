#!/bin/sh -e

# make-bundle.sh
# David Fifield
#
# This script works the magic needed to build Zenmap into a .app bundle for Mac
# OS X. It's complicated because py2app doesn't really support Pango or PyGTK.
#
# It is based on the osx-app.sh script used by Wireshark, which contains the
# following notice:
#
# AUTHORS
#		 Kees Cook <kees@outflux.net>
#		 Michael Wybrow <mjwybrow@users.sourceforge.net>
#		 Jean-Olivier Irisson <jo.irisson@gmail.com>
#
# Copyright (C) 2005 Kees Cook
# Copyright (C) 2005-2007 Michael Wybrow
# Copyright (C) 2007 Jean-Olivier Irisson
#
# Released under GNU GPL, read the file 'COPYING' for more information

# This script relies on having an installation of MacPorts in $(LIBPREFIX),
# configured as you wish. See README for instructions on how to make a build
# environment. You need to have installed the packages py26-gtk and
# py26-py2app.

LIBPREFIX=$HOME/macports-10.5
PYTHON=$LIBPREFIX/bin/python2.6
PKG_CONFIG=$LIBPREFIX/bin/pkg-config
APP_NAME=Zenmap
BASE=dist/$APP_NAME.app/Contents
SCRIPT_DIR=`dirname "$0"`

CC=${CC:-gcc}
CFLAGS=${CFLAGS:--Wall}

echo "Running $0."

echo "Removing old build."
rm -rf build dist

echo "Compiling using py2app."
$PYTHON setup.py py2app --no-strip

# Delete a library that causes compatibility problems with OS X 10.9.
# http://seclists.org/nmap-dev/2013/q4/85
rm -f $BASE/Frameworks/libxml2.2.dylib

mkdir -p $BASE/Resources/etc
mkdir -p $BASE/Resources/lib

gtk_version=`$PKG_CONFIG --variable=gtk_binary_version gtk+-2.0`
echo "Copying GTK+ $gtk_version files."
mkdir -p $BASE/Resources/lib/gtk-2.0/$gtk_version
cp -R $LIBPREFIX/lib/gtk-2.0/$gtk_version/* $BASE/Resources/lib/gtk-2.0/$gtk_version/

mkdir -p $BASE/Resources/etc/gtk-2.0
cp $SCRIPT_DIR/gtkrc $BASE/Resources/etc/gtk-2.0/

echo "Updating paths in GTK+ .so files"
ESCAPED_LIBPREFIX=$(echo $LIBPREFIX | sed 's/\([\/\\.]\)/\\\1/g')
find $BASE/Resources/lib/gtk-2.0/$gtk_version/ -type f -name '*.so' | while read so; do
  otool -L "$so" | awk "/$ESCAPED_LIBPREFIX/{print \$1}" | while read dep; do
    install_name_tool -change $dep $(echo $dep | sed "s/$ESCAPED_LIBPREFIX\/lib/@executable_path\/..\/Frameworks/") "$so"
  done
done

pango_version=`$PKG_CONFIG --variable=pango_module_version pango`
echo "Copying Pango $pango_version files."
mkdir -p $BASE/Resources/etc/pango
cat > $BASE/Resources/etc/pango/pangorc.in <<EOF
# This template is filled in at run time by the application.

#
# pangorc file for uninstalled operation.
# We set the path as ../modules, such that it works from any of
# top level build subdirs.
#

[Pango]
ModuleFiles = \${RESOURCES}/etc/pango/pango.modules
EOF
cp $LIBPREFIX/etc/pango/pango.modules $BASE/Resources/etc/pango/

echo "Copying Fontconfig files."
cp -R $LIBPREFIX/etc/fonts $BASE/Resources/etc/
# Remove the dir and cachedir under $LIBPREFIX. The cachedir ~/.fontconfig remains.
sed -i "" 's/ *<dir>'$(echo "$LIBPREFIX" | sed -e 's/\([^a-zA-Z0-9]\)/\\\1/g')'\/share\/fonts<\/dir>//g' $BASE/Resources/etc/fonts/fonts.conf
sed -i "" '/<cachedir>'$(echo "$LIBPREFIX" | sed -e 's/\([^a-zA-Z0-9]\)/\\\1/g')'\/var\/cache\/fontconfig<\/cachedir>/d' $BASE/Resources/etc/fonts/fonts.conf
# Disable hinting to better match the Mac GUI.
cp $LIBPREFIX/share/fontconfig/conf.avail/10-unhinted.conf $BASE/Resources/etc/fonts/conf.d

echo "Renaming main Zenmap executable."
mv $BASE/MacOS/$APP_NAME $BASE/MacOS/zenmap.bin

echo "Installing wrapper script."
cp $SCRIPT_DIR/zenmap_wrapper.py $BASE/MacOS/

echo "Compiling and installing authorization wrapper."
echo $CC $CPPFLAGS $CFLAGS $LDFLAGS -framework Security -o $BASE/MacOS/$APP_NAME $SCRIPT_DIR/zenmap_auth.c
$CC $CPPFLAGS $CFLAGS $LDFLAGS -framework Security -o $BASE/MacOS/$APP_NAME $SCRIPT_DIR/zenmap_auth.c
