## $Id: Makefile.am,v 1.16 2005/02/10 17:06:36 dugsong Exp $

include $(top_srcdir)/Makefile.am.common

lib_LTLIBRARIES = libdnet.la

libdnet_la_SOURCES = addr-util.c addr.c blob.c ip-util.c ip6.c rand.c

EXTRA_libdnet_la_SOURCES = 

libdnet_la_LIBADD = @LTLIBOBJS@

libdnet_la_LDFLAGS = -version-info 1:0:0
