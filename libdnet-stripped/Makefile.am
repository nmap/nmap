## $Id: Makefile.am,v 1.7 2004/01/03 08:52:22 dugsong Exp $

include $(top_srcdir)/Makefile.am.common

SUBDIRS =	include src 

bin_SCRIPTS =	dnet-config

EXTRA_DIST =	LICENSE Makefile.am.common acconfig.h

CLEANFILES =	dnet-config

AUX_DIST =	$(ac_aux_dir)/acinclude.m4	\
		$(ac_aux_dir)/config.guess	\
		$(ac_aux_dir)/config.sub	\
		$(ac_aux_dir)/install-sh	\
		$(ac_aux_dir)/ltmain.sh		\
		$(ac_aux_dir)/missing		\
		$(ac_aux_dir)/mkinstalldirs

dist-hook:
	(cd $(distdir) && mkdir $(ac_aux_dir))
	for file in $(AUX_DIST); do \
		cp $$file $(distdir)/$$file; \
	done
