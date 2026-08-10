#!/bin/sh -e
#
# Copyright (c) 1994, 1996
#	The Regents of the University of California.  All rights reserved.
#
# Redistribution and use in source and binary forms are permitted
# provided that this notice is preserved and that due credit is given
# to the University of California at Berkeley. The name of the University
# may not be used to endorse or promote products derived from this
# software without specific prior written permission. This software
# is provided ``as is'' without express or implied warranty.
#
#	@(#)mkdep.sh	5.11 (Berkeley) 5/5/88
#

MAKE=Makefile			# default makefile name is "Makefile"
CC=cc				# default C compiler is "cc"
DEPENDENCY_CFLAG=-M		# default dependency-generation flag is -M
SOURCE_DIRECTORY=.		# default source directory is the current directory

# No command-line flags seen yet.
flags=""
while :
	do case "$1" in
		# -c allows you to specify the C compiler
		-c)
			CC=$2
			shift; shift ;;

		# -f allows you to select a makefile name
		-f)
			MAKE=$2
			shift; shift ;;

		# -m allows you to specify the dependency-generation flag
		-m)
			DEPENDENCY_CFLAG=$2
			shift; shift ;;

		# the -p flag produces "program: program.c" style dependencies
		# so .o's don't get produced
		-p)
			SED='s;\.o;;'
			shift ;;

		# -s allows you to specify the source directory
		-s)
			SOURCE_DIRECTORY=$2
			shift; shift ;;

		# -include takes an argument
		-include)
			flags="$flags $1 $2"
			shift; shift ;;

		# other command-line flag
		-*)
			flags="$flags $1"
			shift ;;

		*)
			break ;;
	esac
done

if [ $# = 0 ] ; then
	echo 'usage: mkdep [-p] [-c cc] [-f makefile] [-m dependency-cflag] [-s source-directory] [flags] file ...'
	exit 1
fi

if [ ! -w "$MAKE" ]; then
	echo "mkdep: no writeable file \"$MAKE\""
	exit 1
fi

TMP=${TMPDIR:-/tmp}/mkdep$$

trap 'rm -f "$TMP" ; exit 1' HUP INT QUIT PIPE TERM

cp "$MAKE" "${MAKE}.bak"

sed -e '/DO NOT DELETE THIS LINE/,$d' < "$MAKE" > "$TMP"

cat << _EOF_ >> "$TMP"
# DO NOT DELETE THIS LINE -- mkdep uses it.
# DO NOT PUT ANYTHING AFTER THIS LINE, IT WILL GO AWAY.

_EOF_

# If your compiler doesn't have -M, add it.  If you can't, the next two
# lines will try and replace the "cc -M".  The real problem is that this
# hack can't deal with anything that requires a search path, and doesn't
# even try for anything using bracket (<>) syntax.
#
# grep -E '^#include[[:blank:]]*".*"' /dev/null $* |
# sed -e 's/:[^"]*"\([^"]*\)".*/: \1/' -e 's/\.c/.o/' |

#
# Construct a list of source files with paths relative to the source directory.
#
sources=""
for srcfile in "$@"
do
	sources="$sources $SOURCE_DIRECTORY/$srcfile"
done

# XXX this doesn't work with things like "-DDECLWAITSTATUS=union\ wait"
# $flags and $sources are meant to expand
# shellcheck disable=SC2086
"$CC" "$DEPENDENCY_CFLAG" $flags $sources |
sed "
	s; \./; ;g
	$SED" >> "$TMP"

cat << _EOF_ >> "$TMP"

# IF YOU PUT ANYTHING HERE IT WILL GO AWAY
_EOF_

# copy to preserve permissions
cp "$TMP" "$MAKE"
rm -f "${MAKE}.bak" "$TMP"
exit 0
