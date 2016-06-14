#!/bin/sh

name=`basename "$0"`
tmp="$0"
tmp=`dirname "$tmp"`
tmp=`dirname "$tmp"`
bundle=`dirname "$tmp"`
bundle_contents="$bundle"/Contents
bundle_res="$bundle_contents"/Resources
bundle_lib="$bundle_res"/lib
bundle_bin="$bundle_res"/bin
bundle_data="$bundle_res"/share
bundle_etc="$bundle_res"/etc

export DYLD_LIBRARY_PATH="$bundle_lib"
export XDG_CONFIG_DIRS="$bundle_etc"/xdg
export XDG_DATA_DIRS="$bundle_data"
export GTK_DATA_PREFIX="$bundle_res"
export GTK_EXE_PREFIX="$bundle_res"
export GTK_PATH="$bundle_res"

export GTK2_RC_FILES="$bundle_etc/gtk-2.0/gtkrc"
export GTK_IM_MODULE_FILE="$bundle_etc/gtk-2.0/gtk.immodules"
export GDK_PIXBUF_MODULE_FILE="$bundle_lib/gdk-pixbuf-2.0/2.10.0/loaders.cache"
export PANGO_LIBDIR="$bundle_lib"
export PANGO_SYSCONFDIR="$bundle_etc"

#Set $PYTHON to point inside the bundle
export PYTHON="$bundle_contents/MacOS/python"
#Add the bundle's python modules
PYTHONHOME="$bundle_res"
export PYTHONHOME
PYTHONPATH="$bundle_res/lib/zenmap"
export PYTHONPATH

# We need a UTF-8 locale.
if [ -z ${lang+x} ]; then 
  # lang is unset 
  lang=`defaults read /Library/Preferences/.GlobalPreferences AppleLanguages 2>/dev/null | awk '{ print $1 }' | head -n2 | tail -n1 | sed 's/\,/ /'`
  if [ -z ${lang+x} ]; then
    # lang is still unset 
    lang=`defaults read .GlobalPreferences AppleLocale 2>/dev/null`
  fi
  export LANG="`grep \"\`echo $lang\`_\" /usr/share/locale/locale.alias |  tail -n1 | sed 's/\./ /' | awk '{print $2}'`.UTF-8"
fi

if test -f "$bundle_lib/charset.alias"; then
    export CHARSETALIASDIR="$bundle_lib"
fi

# Extra arguments can be added in environment.sh.
EXTRA_ARGS=
if test -f "$bundle_res/environment.sh"; then
  source "$bundle_res/environment.sh"
fi

# Strip out the argument added by the OS.
if /bin/expr "x$1" : "x-psn_.*" > /dev/null; then
    shift 1
fi

# Make the real UID equal the effective UID. They are unequal when running
# with privileges under AuthorizationExecuteWithPrivileges. GTK+ refuses to
# run if they are different
# Note that we're calling $PYTHON here to override the version in zenmap's shebang.
$EXEC $PYTHON -c $'import os\nif os.getuid()!=os.geteuid():os.setuid(os.geteuid())\n'"os.execl(\"$PYTHON\",\"$PYTHON\",\"$bundle_bin/zenmap\")"
