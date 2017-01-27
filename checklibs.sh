#!/bin/sh

NDIR=${NDIR:-$PWD}

newest() {
    perl -nE'END{$,=".";say unpack"C*",$m}$m=($m,$n)[($n=pack"C*",split/\./) gt$m]'
}

trim_version() {
    echo $1 | sed 's/\(^\|\.\)0*/\1/g'
}

check_libpcre() {
    PCRE_SOURCE="ftp://ftp.csx.cam.ac.uk/pub/software/programming/pcre/"
    PCRE_MAJOR=""
    PCRE_MINOR=""
    eval $(grep '^PCRE_MAJOR=' $NDIR/libpcre/configure)
    eval $(grep '^PCRE_MINOR=' $NDIR/libpcre/configure)
    PCRE_VERSION="$PCRE_MAJOR.$PCRE_MINOR"
    PCRE_LATEST=$(curl -ls $PCRE_SOURCE | perl -lne 'if(/pcre-(\d+.\d+).tar.gz$/){print $1}' | newest)
    if [ "$PCRE_VERSION" != "$PCRE_LATEST" ]; then
        echo "Newer version of libpcre available"
        echo "  Current:" $PCRE_VERSION
        echo "  Latest: " $PCRE_LATEST
        echo "  Source: $PCRE_SOURCE"
    fi
}

check_libpcap() {
    PCAP_SOURCE="http://www.tcpdump.org/release/"
    PCAP_VERSION=$(cat $NDIR/libpcap/VERSION)
    PCAP_LATEST=$(curl -s $PCAP_SOURCE | perl -lne 'if(/libpcap-([\d.]+).tar.gz/){print $1}' | newest)
    if [ "$PCAP_VERSION" != "$PCAP_LATEST" ]; then
        echo "Newer version of libpcap available"
        echo "  Current:" $PCAP_VERSION
        echo "  Latest: " $PCAP_LATEST
        echo "  Source: $PCAP_SOURCE"
    fi
}

check_liblua() {
    LUA_SOURCE="http://www.lua.org/ftp/"
    cat >check_liblua.c <<EOC
#include "lua.h"
#include<stdio.h>
int main(int argc,char *argv[]){
printf("%s\\n", LUA_RELEASE);
return 0;
}
EOC
    cc -I"$NDIR/liblua" -o check_liblua check_liblua.c
    LUA_VERSION=$(./check_liblua)
    LUA_VERSION=${LUA_VERSION#Lua }
    rm check_liblua check_liblua.c
    LUA_LATEST=$(curl -s $LUA_SOURCE | perl -lne 'if(/lua-([\d.]+).tar.gz/){print $1}' | newest)
    if [ "$LUA_VERSION" != "$LUA_LATEST" ]; then
        echo "Newer version of liblua available"
        echo "  Current:" $LUA_VERSION
        echo "  Latest: " $LUA_LATEST
        echo "  Source: $LUA_SOURCE"
    fi
}

check_liblinear() {
    LINEAR_SOURCE="http://www.csie.ntu.edu.tw/~cjlin/liblinear/"
    echo "Can't check liblinear, no version information is available"
    LINEAR_LATEST=$(curl -s $LINEAR_SOURCE | perl -lne 'if(/The current release \(([^)]+)\) of <b>LIBLINEAR/){print $1;exit 0}')
    echo "  Latest:" $LINEAR_LATEST
}

check_libpcre
check_libpcap
check_liblua
check_liblinear
