#!/bin/sh

# nsock regression test suite
# Same license as nmap -- see http://nmap.org/book/man-legal.html

EXEC_MAIN=./tests_main

if [ -n "$1" ]
then
  case "$1" in
    "gdb")
        TRACER="gdb --args"
        ;;

    "trace")
        TRACER="strace"
        ;;

    "leak")
        TRACER="valgrind --leak-check=yes"
        ;;

    "-h")
        echo "Usage: `basename $0` [gdb|trace|leak]"
        exit 0
        ;;

    *)
        echo "Unknown mode $1"
        exit 1
        ;;
  esac
fi

$TRACER $EXEC_MAIN
