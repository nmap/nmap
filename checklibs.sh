#!/bin/sh

NDIR=${NDIR:-$PWD}

newest() {
  sort -V | tail -n 1
}

trim_version() {
    echo $1 | sed 's/\(^\|\.\)0*/\1/g'
}

check_libpcre() {
    PCRE_SOURCE="https://github.com/PCRE2Project/pcre2/releases/latest"
    PCRE_MAJOR=""
    PCRE_MINOR=""
    eval $(grep '^PCRE2_MAJOR=' $NDIR/libpcre/configure)
    eval $(grep '^PCRE2_MINOR=' $NDIR/libpcre/configure)
    PCRE_VERSION="$PCRE2_MAJOR.$PCRE2_MINOR"
    PCRE_LATEST=$(curl -Ls -I $PCRE_SOURCE | tee tmp.txt | perl -lne 'if(m|^Location:.*/tag/pcre2-(\d+.\d+)[\r\n]*$|){print $1;exit(0)}')
    if [ "$PCRE_VERSION" != "$PCRE_LATEST" ]; then
        echo "Newer version of libpcre available"
        echo "  Current:" $PCRE_VERSION
        echo "  Latest: " $PCRE_LATEST
        echo "  Source: $PCRE_SOURCE"
    else
      echo "libpcre: $PCRE_VERSION"
    fi
}

check_libpcap() {
    PCAP_SOURCE="https://www.tcpdump.org/release/"
    PCAP_VERSION=$(cat $NDIR/libpcap/VERSION 2>/dev/null || cat $NDIR/libpcap/VERSION.txt)
    PCAP_LATEST=$(curl -Ls $PCAP_SOURCE | perl -lne 'if(/libpcap-([\d.]+).tar.gz/){print $1}' | newest)
    if [ "$PCAP_VERSION" != "$PCAP_LATEST" ]; then
        echo "Newer version of libpcap available"
        echo "  Current:" $PCAP_VERSION
        echo "  Latest: " $PCAP_LATEST
        echo "  Source: $PCAP_SOURCE"
    else
      echo "libpcap: $PCAP_VERSION"
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
    LUA_LATEST=$(curl -Ls $LUA_SOURCE | perl -lne 'if(/lua-([\d.]+).tar.gz/){print $1}' | newest)
    if [ "$LUA_VERSION" != "$LUA_LATEST" ]; then
        echo "Newer version of liblua available"
        echo "  Current:" $LUA_VERSION
        echo "  Latest: " $LUA_LATEST
        echo "  Source: $LUA_SOURCE"
    else
      echo "liblua: $LUA_VERSION"
    fi
}

check_liblinear() {
    LINEAR_SOURCE="https://www.csie.ntu.edu.tw/~cjlin/liblinear/"
    LINEAR_VERSION=$(awk '$2=="LIBLINEAR_VERSION"{print$3;exit}' $NDIR/liblinear/linear.h | sed 's/./&./1')
    LINEAR_LATEST=$(curl -Ls $LINEAR_SOURCE | perl -lne 'if(/liblinear-([\d.]+).tar.gz/){print $1}' | newest)
    if [ "$LINEAR_VERSION" != "$LINEAR_LATEST" ]; then
        echo "Newer version of liblinear available"
        echo "  Current:" $LINEAR_VERSION
        echo "  Latest: " $LINEAR_LATEST
        echo "  Source: $LINEAR_SOURCE"
    else
      echo "liblinear: $LINEAR_VERSION"
    fi
}

check_zlib() {
    ZLIB_SOURCE="https://zlib.net/"
    ZLIB_VERSION=$(awk '$2=="ZLIB_VERSION"{print$3;exit}' $NDIR/libz/zlib.h | tr -d '"')
    ZLIB_LATEST=$(curl -Ls $ZLIB_SOURCE | perl -lne 'if(/zlib-([\d.]+).tar.gz/){print $1}' | newest)
    if [ "$ZLIB_VERSION" != "$ZLIB_LATEST" ]; then
        echo "Newer version of zlib available"
        echo "  Current:" $ZLIB_VERSION
        echo "  Latest: " $ZLIB_LATEST
        echo "  Source: $ZLIB_SOURCE"
    else
      echo "zlib: $ZLIB_VERSION"
    fi
}

check_libssh2() {
    LIBSSH2_SOURCE="https://libssh2.org/download/"
    LIBSSH2_VERSION=$(awk '$2=="LIBSSH2_VERSION"{print$3;exit}' $NDIR/libssh2/include/libssh2.h | tr -d '"')
    LIBSSH2_LATEST=$(curl -Ls $LIBSSH2_SOURCE | perl -lne 'if(/libssh2-([\d.]+).tar.gz/){print $1}' | newest)
    if [ "$LIBSSH2_VERSION" != "$LIBSSH2_LATEST" ]; then
        echo "Newer version of libssh2 available"
        echo "  Current:" $LIBSSH2_VERSION
        echo "  Latest: " $LIBSSH2_LATEST
        echo "  Source: $LIBSSH2_SOURCE"
    else
      echo "libssh2: $LIBSSH2_VERSION"
    fi
}

check_libpcre
check_libpcap
check_liblua
check_liblinear
check_zlib
check_libssh2
