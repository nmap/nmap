## $Id: Makefile.am 618 2006-01-15 06:42:19Z dugsong $

include $(top_srcdir)/Makefile.am.common

SUBDIRS =	include src

bin_SCRIPTS =	dnet-config

EXTRA_DIST =	LICENSE Makefile.am.common acconfig.h

CLEANFILES =	dnet-config

aux_dir = config

AUX_DIST = $(aux_dir)/acinclude.m4

ACLOCAL_AMFLAGS = -I config
