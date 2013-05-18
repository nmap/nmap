#!/bin/bash

# nsock regression test suite
# Same license as nmap -- see http://nmap.org/book/man-legal.html

# hackish, I should consider using a configuration file.
PORT_UDP=$(grep "PORT_UDP " test-common.h | awk '{print $3}')
PORT_TCP=$(grep "PORT_TCP " test-common.h | awk '{print $3}')
PORT_TCPSSL=$(grep "PORT_TCPSSL " test-common.h | awk '{print $3}')

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


function setup_echo_udp() {
  ncat -l --udp --sh-exec cat localhost $PORT_UDP &
  pid_udp=$!
  echo "started UDP listener on port $PORT_UDP (pid $pid_udp)"
}

function setup_echo_tcp() {
  ncat -l --keep-open --sh-exec cat localhost $PORT_TCP &
  pid_tcp=$!
  echo "started TCP listener on port $PORT_TCP (pid $pid_tcp)"
}

function setup_echo_tcpssl() {
  ncat -l --ssl --keep-open --sh-exec cat localhost $PORT_TCPSSL &
  pid_tcpssl=$!
  echo "started TCP SSL listener on port $PORT_TCPSSL (pid $pid_tcpssl)"
}

function cleanup_all() {
  kill -s KILL $@ 2>&1 >> /dev/null
}

function main() {
  setup_echo_udp $PORT_UDP
  setup_echo_tcp $PORT_TCP
  setup_echo_tcpssl $PORT_TCPSSL

  $TRACER $EXEC_MAIN

  cleanup_all $pid_udp $pid_tcp $pid_tcpssl
}

main
