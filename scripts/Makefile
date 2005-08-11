
CC=gcc
CPP=g++
INCLUDE_FLAGS= -I.. -I../nbase -I../libpcap-possiblymodified
LINK_FLAGS=-L.. -L../nbase -L../libpcap-possiblymodified
NMAP_OBJS=../osscan.o ../nmap_error.o ../utils.o ../tcpip.o ../output.o ../nmap.o ../scan_engine.o ../portlist.o ../timing.o ../nmap_rpc.o ../charpool.o ../services.o ../targets.o ../idle_scan.o ../MACLookup.o ../protocols.o ../FingerPrintResults.o ../NmapOps.o ../TargetGroup.o ../Target.o ../NmapOutputTable.o ../service_scan.o ../nsock/src/libnsock.a
DEFINES=-DHAVE_CONFIG_H=1
DATAFILES = nmap-os-fingerprints nmap-service-probes nmap-services nmap-rpc nmap-protocols nmap-mac-prefixes
SHTOOL = ../shtool
LIBPCAPDIR=libpcap-possiblymodified
NBASEDIR=nbase

all: fingermatch fingerdiff servicematch

dummy:

fingermatch: dummy
	$(CPP) -g -Wall $(INCLUDE_FLAGS) $(LINK_FLAGS) $(DEFINES) -o $@ $@.cc $(NMAP_OBJS) -lm -lnbase -lpcap -lpcre -lssl -lcrypt -ldnet

fingerdiff: dummy
	$(CPP) -g -Wall $(INCLUDE_FLAGS) $(LINK_FLAGS) $(DEFINES) -o $@ $@.cc $(NMAP_OBJS) -lm -lnbase -lpcap -lpcre -lssl -lcrypt -ldnet

servicematch: dummy
	$(CPP) -g -Wall $(INCLUDE_FLAGS) $(LINK_FLAGS) $(DEFINES) -o $@ $@.cc $(NMAP_OBJS) -lm -lnbase -lpcap -lpcre -lssl -lcrypt -ldnet

web:
	test x$(wroot) != x
	cd ../docs && cp -a nmap_gpgkeys.txt nmap_manpage*.html nmap*.1 \
                            xnmap.1 nmap.usage.txt nmap.dtd nmap.xsl \
                            leet-nmap-ascii-art.txt $(wroot)/nmap/data/
	./sort-prints.pl ../nmap-os-fingerprints > nos && mv nos ../nmap-os-fingerprints
	./produceosclasschoosebox.pl ../nmap-os-fingerprints > $(wroot)/nmap/data/os-classes.txt
	cd .. && cp -a CHANGELOG HACKING COPYING COPYING.OpenSSL INSTALL \
                       $(DATAFILES) README-WIN32 mswin32/nmap_performance.reg $(wroot)/nmap/data
	./sign_release.pl $(wroot)/nmap/dist

	find $(wroot)/nmap/data/ -type f -exec chmod 644 '{}' \;
	find $(wroot)/nmap/dist/sigs -type f -exec chmod 644 '{}' \;

# This is unsafe on shared systems, should use mktemp
distro: 
	cd .. && autoconf
	rm -f ../config.cache
	cd .. && ./configure
	cd ../$(LIBPCAPDIR) && ./configure
	$(MAKE) -C .. clean
	$(MAKE) -C ..
	../nmap -h > /dev/null    #Make sure nmap exists
	rm -f ../docs/nmap.usage.txt	
	../nmap -h > ../docs/nmap.usage.txt 
	rm -f ../docs/nmap_manpage.html
# nodepage option is included in man2html because of bug in that program which causes it to
# drop lines if you let it try to delete page breaks
	nroff -man ../docs/nmap.1 | man2html -nodepage -title 'Nmap network security scanner man page' > ../docs/nmap_manpage.html
	nroff -man ../docs/nmap_french.1 | man2html -nodepage -title 'Nmap network security scanner man page (French translation)' > ../docs/nmap_manpage-fr.html
	nroff -man ../docs/nmap_german.1 | man2html -nodepage -title 'Nmap network security scanner man page (German translation)' > ../docs/nmap_manpage-de.html
	nroff -man ../docs/nmap_italian.1 | man2html -nodepage -title 'Nmap network security scanner man page (Italian translation)' > ../docs/nmap_manpage-it.html
	nroff -man ../docs/nmap_latvian.1 | man2html -nodepage -title 'Nmap network security scanner man page (Latvian translation)' > ../docs/nmap_manpage-lv.html
	nroff -Tlatin1 -man ../docs/nmap_lithuanian.1 | man2html -nodepage -title 'Nmap network security scanner man page (Lithuanian translation)' > ../docs/nmap_manpage-lt.html
	nroff -man ../docs/nmap_russian.1 | man2html -nodepage -title 'Nmap network security scanner man page (Russian translation)' > ../docs/nmap_manpage-ru.html
# We need a content-type for the Lithuanian version
	sr '<HEAD>' '<HEAD><META http-equiv="Content-Type" content="text/html; charset=windows-1257">' ../docs/nmap_manpage-lt.html
	nroff -man ../docs/nmap_portuguese.1 | man2html -nodepage -title 'Nmap network security scanner man page (Portuguese translation)' > ../docs/nmap_manpage-pt.html
	nroff -man ../docs/nmap_spanish.1 | man2html -nodepage -title 'Nmap network security scanner man page (Spanish translation)' > ../docs/nmap_manpage-es.html
	rm -rf /usr/tmp/nmap-$(NMAP_VERSION)
	mkdir /usr/tmp/nmap-$(NMAP_VERSION)
# Make the RPM .spec file
	sed -e s/\@VERSION\@/$(NMAP_VERSION)/g ../nmap.spec.in > ../nmap-$(NMAP_VERSION)-1.spec
# Canonicalize and sort Nmap OS fingerprint DB
	sort-prints.pl ../nmap-os-fingerprints > nos && mv nos ../nmap-os-fingerprints
	$(MAKE) -C .. clean
	cd .. && rm -f $(LIBPCAPDIR)/config.cache $(LIBPCAPDIR)/Makefile
	cd .. && unix2dos README-WIN32
	cd .. && cp -ra $(SRCS) $(DEPS) $(DATAFILES) nmapfe.desktop \
         configure.ac config.h.in aclocal.m4 nmap_winconfig.h Makefile.in \
         configure shtool install-sh config.guess \
         nmap-$(NMAP_VERSION)-1.spec config.sub INSTALL README-WIN32 COPYING \
         COPYING.OpenSSL CHANGELOG HACKING /usr/tmp/nmap-$(NMAP_VERSION)
	$(SHTOOL) mkdir /usr/tmp/nmap-$(NMAP_VERSION)/mswin32
	cd ../mswin32; cp -ra *.[hHcC] *.cc ARPA NET NETINET RPC icon1.ico \
                    ifaddrlist.h lib libpcap-note.txt nmap.rc \
                    nmap_performance.reg nmap.sln nmap.vcproj pcap-include \
                    /usr/tmp/nmap-$(NMAP_VERSION)/mswin32

	$(SHTOOL) mkdir /usr/tmp/nmap-$(NMAP_VERSION)/$(LIBPCAPDIR)
	cd ../$(LIBPCAPDIR); cp -ra --parents SUNOS4/nit_if.o.sparc \
           SUNOS4/nit_if.o.sun3 SUNOS4/nit_if.o.sun4c.4.0.3c CHANGES \
           CREDITS FILES INSTALL.txt LICENSE Makefile.in \
           NMAP_MODIFICATIONS README README.aix README.linux \
           README.tru64 TODO VERSION acconfig.h aclocal.m4 \
           arcnet.h bpf_dump.c bpf_image.c config.guess config.h.in \
           config.sub configure configure.ac etherent.c ethertype.h gencode.c \
           gencode.h grammar.y inet.c install-sh llc.h mkdep nametoaddr.c \
           nlpid.h optimize.c pcap-bpf.c pcap-dlpi.c pcap-enet.c pcap-int.h \
           pcap-linux.c pcap-namedb.h pcap-nit.c pcap-nit.h pcap-null.c \
           pcap-pf.c pcap-pf.h pcap-snit.c pcap-snoop.c pcap.3 pcap.c pcap.h \
           ppp.h savefile.c scanner.c scanner.l sll.h tokdefs.h \
           bpf/net/bpf_filter.c bpf/net/bpf.h lbl/os-aix4.h lbl/os-osf4.h \
           lbl/os-solaris2.h lbl/os-sunos4.h lbl/os-ultrix4.h lbl/os-hpux11.h \
           lbl/os-osf5.h atmuni31.h config.h fad-getad.c fad-gifc.c \
           fad-glifc.c fad-null.c fad-win32.c pcap-bpf.h pcap-dag.c \
           pcap-dag.h version.h grammar.c pcap-stdinc.h pcap-win32.c pf.h \
           rawss7.h README.dag README.hpux README.Win32 snprintf.c \
           sunatmpos.h Win32/Include/addrinfo.h Win32/Include/Gnuc.h \
           Win32/Include/arpa/nameser.h Win32/Include/net/if.h \
           Win32/Include/net/netdb.h Win32/Include/net/paths.h \
           Win32/Include/bittypes.h Win32/Include/cdecl_ext.h \
           Win32/Include/inetprivate.h Win32/Include/ip6_misc.h \
           Win32/Include/sockstorage.h Win32/Prj/libpcap.dsp \
           Win32/Prj/libpcap.dsw Win32/Src/getnetbynm.c Win32/Src/ffs.c \
           Win32/Src/getaddrinfo.c Win32/Src/getnetent.c Win32/Src/getopt.c \
           Win32/Src/getservent.c Win32/Src/inet_aton.c Win32/Src/inet_net.c \
           Win32/Src/inet_pton.c /usr/tmp/nmap-$(NMAP_VERSION)/$(LIBPCAPDIR)
	$(SHTOOL) mkdir /usr/tmp/nmap-$(NMAP_VERSION)/docs
	cd ../docs; cp -ra README nmap_gpgkeys.txt \
                    nmap-fingerprinting-article.txt \
                    nmap.deprecated.txt nmap.usage.txt nmap_doc.html \
                    nmap_manpage-de.html nmap_manpage-es.html \
                    nmap_manpage-fr.html nmap_manpage-it.html \
                    nmap_manpage-lt.html nmap_manpage-pt.html \
                    nmap_manpage-ru.html nmap_manpage.html \
                    nmap.1 nmapfe.1 nmap_french.1 nmap_german.1 \
                    nmap_italian.1 nmap_lithuanian.1 nmap_portuguese.1 \
                    nmap_spanish.1 nmap_russian.1 xnmap.1 nmap.dtd nmap.xsl \
                    leet-nmap-ascii-art.txt /usr/tmp/nmap-$(NMAP_VERSION)/docs
	$(SHTOOL) mkdir /usr/tmp/nmap-$(NMAP_VERSION)/nmapfe
	cd ../nmapfe; cp -ra Makefile.in aclocal.m4 configure configure.ac \
	              nmapfe.c nmapfe.h nmapfe_sig.c nmapfe_sig.h \
	              nmapfe_error.c nmapfe_error.h NmapFE.dsp nmapfe.dsw \
	              /usr/tmp/nmap-$(NMAP_VERSION)/nmapfe

	$(SHTOOL) mkdir /usr/tmp/nmap-$(NMAP_VERSION)/nbase
	cd ../$(NBASEDIR); cp -ra Makefile.in aclocal.m4 configlocal.m4 \
                        nbase.vcproj configure configure.ac nbase_config.h.in \
                        *.c *.h CHANGELOG /usr/tmp/nmap-$(NMAP_VERSION)/nbase

	$(SHTOOL) mkdir /usr/tmp/nmap-$(NMAP_VERSION)/libpcre
	cd ../libpcre; cp -ra AUTHORS chartables.c config.guess config.in \
                        config.sub configure configure.ac COPYING dftables.c \
                        get.c INSTALL install-sh internal.h libpcre.vcproj \
                        LICENCE ltmain.sh Makefile.in maketables.c makevp.bat \
                        mkinstalldirs NEWS NMAP_MODIFICATIONS NON-UNIX-USE \
                        pcre.c pcre-config.in pcre.def pcre.h pcre.in \
                        pcre_win.h pcre_winconfig.h pcreposix.c pcreposix.h \
                        perltest printint.c README study.c \
                        /usr/tmp/nmap-$(NMAP_VERSION)/libpcre

	$(SHTOOL) mkdir /usr/tmp/nmap-$(NMAP_VERSION)/libdnet-stripped
	cd ../$(LIBDNETDIR); cp -ra NMAP_MODIFICATIONS \
              libdnet-stripped.vcproj acconfig.h aclocal.m4 config \
              configure configure.in dnet-config.in include INSTALL \
              libtool LICENSE Makefile Makefile.am Makefile.am.common \
              Makefile.in README src THANKS TODO \
              /usr/tmp/nmap-$(NMAP_VERSION)/libdnet-stripped

	$(SHTOOL) mkdir /usr/tmp/nmap-$(NMAP_VERSION)/nsock
	$(SHTOOL) mkdir /usr/tmp/nmap-$(NMAP_VERSION)/nsock/include
	$(SHTOOL) mkdir /usr/tmp/nmap-$(NMAP_VERSION)/nsock/src
	cp ../nsock/nsock.vcproj /usr/tmp/nmap-$(NMAP_VERSION)/nsock/
	cd ../nsock/include; cp -ra nsock.h /usr/tmp/nmap-$(NMAP_VERSION)/nsock/include/
	cd ../nsock/src; cp -ra  aclocal.m4 config.guess config.sub \
                            configure configure.ac error.c error.h \
                            filespace.c filespace.h gh_list.c gh_list.h \
                            install-sh Makefile.in netutils.c netutils.h \
                            nsock_config.h.in nsock_connect.c nsock_core.c \
                            nsock_event.c nsock_internal.h nsock_iod.c \
                            nsock_pool.c nsock_read.c nsock_ssl.h \
                            nsock_ssl.c nsock_timers.c \
                            nsock_write.c nsock_utils.c nsock_utils.h \
                            /usr/tmp/nmap-$(NMAP_VERSION)/nsock/src/

	rm -f /usr/tmp/nmap-$(NMAP_VERSION)/nbase/nbase_config.h 
# Kill the SVN/CVS crap
	find /usr/tmp/nmap-$(NMAP_VERSION) -type d -name CVS | xargs rm -rf
	find /usr/tmp/nmap-$(NMAP_VERSION) -type d -name .svn | xargs rm -rf
	find /usr/tmp/nmap-$(NMAP_VERSION) -exec chmod go=u-w '{}' \;
	cd /usr/tmp; tar cjf nmap-$(NMAP_VERSION).tar.bz2 nmap-$(NMAP_VERSION)
	cd /usr/tmp; tar czf nmap-$(NMAP_VERSION).tgz nmap-$(NMAP_VERSION)
# Make the actual RPM
# Note -- on newer systems rpmbuild -ta is needed instead.
#	rpm -ta /usr/tmp/nmap-$(NMAP_VERSION).tgz
#	cp -f $(RPMTDIR)/RPMS/i386/nmap-$(NMAP_VERSION)-1.i386.rpm /usr/tmp
#	cp -f $(RPMTDIR)/RPMS/i386/nmap-frontend-$(NMAP_VERSION)-1.i386.rpm /usr/tmp
#	cp -f $(RPMTDIR)/SRPMS/nmap-$(NMAP_VERSION)-1.src.rpm /usr/tmp
	rm -rf /usr/tmp/nmap-$(NMAP_VERSION)
