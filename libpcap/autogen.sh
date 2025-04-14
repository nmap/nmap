#!/bin/sh -e

: "${AUTORECONF:=autoreconf}"

AUTORECONFVERSION=`$AUTORECONF --version 2>&1 | grep "^autoreconf" | sed 's/.*) *//'`

maj=`echo "$AUTORECONFVERSION" | cut -d. -f1`
min=`echo "$AUTORECONFVERSION" | cut -d. -f2`
# The minimum required version of autoconf is currently 2.69.
if [ "$maj" = "" ] || [ "$min" = "" ] || \
   [ "$maj" -lt 2 ] || { [ "$maj" -eq 2 ] && [ "$min" -lt 69 ]; }; then
	cat >&2 <<-EOF
	Please install the 'autoconf' package version 2.69 or later.
	If version 2.69 or later is already installed and there is no
	autoconf default, it may be necessary to set the AUTORECONF
	environment variable to enable the one to use, like:
	AUTORECONF=autoreconf-2.69 ./autogen.sh
	or
	AUTORECONF=autoreconf-2.71 ./autogen.sh
	EOF
	exit 1
fi

echo "$AUTORECONF identification: $AUTORECONFVERSION"
"$AUTORECONF" -f
