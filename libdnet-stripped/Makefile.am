## $Id: Makefile.am,v 1.7 2004/01/03 08:52:22 dugsong Exp $

include $(top_srcdir)/Makefile.am.common

SUBDIRS =	include src 

bin_SCRIPTS =	dnet-config

EXTRA_DIST =	LICENSE Makefile.am.common acconfig.h

CLEANFILES =	dnet-config

aux_dir = config

AUX_DIST =	$(aux_dir)/acinclude.m4

dist-hook:
	(cd $(distdir) && mkdir $(aux_dir))
	for file in $(AUX_DIST); do \
		cp $$file $(distdir)/$$file; \
	done
