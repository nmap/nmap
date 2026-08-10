#!/bin/sh

name=`basename "$0"`
bundle=$(cd `dirname "$0"`;pwd)/../..
bundle_contents="$bundle"/Contents
bundle_res="$bundle_contents"/Resources
bundle_lib="$bundle_res"/lib
bundle_bin="$bundle_res"/bin
bundle_data="$bundle_res"/share
bundle_etc="$bundle_res"/etc

export DYLD_LIBRARY_PATH="$bundle_lib"
# Strip out the argument added by the OS.
if /bin/expr "x$1" : "x-psn_.*" > /dev/null; then
    shift 1
fi

exec "$bundle_bin"/"$name" "$@"
