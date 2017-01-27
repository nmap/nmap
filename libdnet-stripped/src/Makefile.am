## $Id: Makefile.am 625 2006-01-19 06:11:01Z dugsong $

include $(top_srcdir)/Makefile.am.common

lib_LTLIBRARIES = libdnet.la

libdnet_la_SOURCES = addr-util.c addr.c blob.c ip-util.c ip6.c rand.c

libdnet_la_LIBADD = @LTLIBOBJS@

libdnet_la_LDFLAGS = -version-info 1:1:0
