
CC=gcc
CXX=g++
CXXFLAGS=-g
INCLUDE_FLAGS= -I.. -I../nbase -I../libpcap -I../libdnet-stripped/include/
LINK_FLAGS=-L.. -L../nbase -L../libpcap 
NMAP_OBJS=../osscan.o ../osscan2.o ../nmap_error.o ../utils.o ../tcpip.o ../output.o ../nmap.o ../scan_engine.o ../portlist.o ../timing.o ../nmap_rpc.o ../charpool.o ../services.o ../targets.o ../idle_scan.o ../MACLookup.o ../protocols.o ../FingerPrintResults.o ../NmapOps.o ../TargetGroup.o ../Target.o ../NmapOutputTable.o ../service_scan.o ../nmap_tty.o ../nmap_dns.o ../nsock/src/libnsock.a ../libdnet-stripped/src/.libs/libdnet.a
DEFINES=-DHAVE_CONFIG_H=1
DATAFILES = nmap-os-fingerprints nmap-os-db nmap-service-probes nmap-services nmap-rpc nmap-protocols nmap-mac-prefixes
SHTOOL = ../shtool
LIBPCAPDIR=libpcap
NBASEDIR=nbase

all: fingerfix fingermatch fingerdiff servicematch

dummy:

.cc.o: dummy
	$(CXX) -c $(CXXFLAGS) $(INCLUDE_FLAGS) $(DEFINES) $< -o $@

fingerfix: dummy
	$(CXX) $(CXXFLAGS) -Wall $(INCLUDE_FLAGS) $(LINK_FLAGS) $(DEFINES) -o $@ $@.cc fingerlib.o $(NMAP_OBJS) -lm -lnbase -lpcap -lpcre -lssl -lcrypt

fingermatch: dummy
	$(CXX) $(CXXFLAGS) -Wall $(INCLUDE_FLAGS) $(LINK_FLAGS) $(DEFINES) -o $@ $@.cc fingerlib.o $(NMAP_OBJS) -lm -lnbase -lpcap -lpcre -lssl -lcrypt

fingerdiff: dummy
	$(CXX) $(CXXFLAGS) -Wall $(INCLUDE_FLAGS) $(LINK_FLAGS) $(DEFINES) -o $@ $@.cc $(NMAP_OBJS) -lm -lnbase -lpcap -lpcre -lssl -lcrypt

servicematch: dummy
	$(CXX) $(CXXFLAGS) -Wall $(INCLUDE_FLAGS) $(LINK_FLAGS) $(DEFINES) -o $@ $@.cc $(NMAP_OBJS) -lm -lnbase -lpcap -lpcre -lssl -lcrypt

web:
	test x$(wroot) != x
	make -C $(wroot)/nmapguide manhtml manxml man manxlate
	cp $(wroot)/nmapguide/nmap.1 ../docs
	cd ../docs && cp -a nmap_gpgkeys.txt nmap_manpage-*.html nmap*.1 \
                            xnmap.1 nmap.usage.txt nmap.dtd nmap.xsl \
                            leet-nmap-ascii-art.txt $(wroot)/nmap/data/
	cp $(wroot)/nmapguide/build/nmap-man.xml $(wroot)/nmap/data/nmap-man.xml
#	./sort-prints.pl ../nmap-os-fingerprints > nos && mv nos ../nmap-os-fingerprints
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
	$(MAKE) -C .. -j3
	../nmap -h > /dev/null    #Make sure nmap exists
	rm -f ../docs/nmap.usage.txt	
	../nmap -h > ../docs/nmap.usage.txt 
	make -C $(wroot)/nmapguide man manxlate
	cp $(wroot)/nmapguide/nmap.1 ../docs
	rm -rf /usr/tmp/nmap-$(NMAP_VERSION)
	mkdir /usr/tmp/nmap-$(NMAP_VERSION)
# Make the RPM .spec file
	sed -e s/\@VERSION\@/$(NMAP_VERSION)/g ../nmap.spec.in > ../nmap-$(NMAP_VERSION)-1.spec
# Canonicalize and sort Nmap OS fingerprint DB
#	sort-prints.pl ../nmap-os-fingerprints > nos && mv nos ../nmap-os-fingerprints
	$(MAKE) -C .. clean
	cd .. && rm -f $(LIBPCAPDIR)/config.cache $(LIBPCAPDIR)/Makefile
	cd .. && unix2dos README-WIN32
	cd .. && cp -a $(SRCS) $(HDRS) $(DATAFILES) nmapfe.desktop \
         configure.ac config.h.in aclocal.m4 Makefile.in \
         configure shtool install-sh config.guess \
         nmap-$(NMAP_VERSION)-1.spec config.sub INSTALL README-WIN32 COPYING \
         COPYING.OpenSSL CHANGELOG HACKING /usr/tmp/nmap-$(NMAP_VERSION)
	$(SHTOOL) mkdir /usr/tmp/nmap-$(NMAP_VERSION)/mswin32
	cd ../mswin32; cp -a --parents ARPA/NAMESER.H ARPA/TFTP.H icon1.ico \
           ifaddrlist.h IPExport.h lib/Packet.lib lib/Wpcap.lib \
           libpcap-note.txt NET/if_arp.h NETINET/UDP.H NETINET/IF_ETHER.H \
           NETINET/IP.H NETINET/TCPIP.H NETINET/IP_ICMP.H NETINET/IN_SYSTM.H \
           NETINET/TCP.H NETINET/TCP_VAR.H NETINET/UDP_VAR.H NETINET/IP_VAR.H \
           nmap_performance.reg nmap.rc nmap.sln nmap.vcproj packet_types.h \
           pcap-include/remote-ext.h pcap-include/memory_t.h \
           pcap-include/pcap-stdinc.h pcap-include/pcap.h \
           pcap-include/semaphore.h pcap-include/Gnuc.h \
           pcap-include/count_packets.h pcap-include/Devioctl.h \
           pcap-include/bucket_lookup.h pcap-include/ip6_misc.h \
           pcap-include/bittypes.h pcap-include/time_calls.h \
           pcap-include/pthread.h pcap-include/Win32-Extensions.h \
           pcap-include/Packet32.h pcap-include/normal_lookup.h \
           pcap-include/pcap-bpf.h pcap-include/sched.h \
           pcap-include/Ntddpack.h pcap-include/tme.h \
           pcap-include/tcp_session.h pcap-include/pcap-int.h \
           winpcap/daemon_mgm.exe winpcap/LICENSE winpcap/NetMonInstaller.exe \
           winpcap/npf_mgm.exe winpcap/npf.sys winpcap/Packet.dll \
           winpcap/pthreadVC.dll winpcap/rpcapd.exe winpcap/WanPacket.dll \
           winpcap/winpcap-nmap.nsi winpcap/wpcap.dll nsis/AddToPath.nsh \
           nsis/Nmap.nsi resource.h RPC/Rpc_cut.h winclude.h winfix.cc \
           winfix.h Makefile /usr/tmp/nmap-$(NMAP_VERSION)/mswin32
	$(SHTOOL) mkdir /usr/tmp/nmap-$(NMAP_VERSION)/$(LIBPCAPDIR)
	cd ../$(LIBPCAPDIR); cp -dp --parents acconfig.h aclocal.m4 arcnet.h \
           atmuni31.h bpf_dump.c bpf_image.c CHANGES \
           config.guess config.h.in config.sub configure configure.ac \
           CREDITS etherent.c ethertype.h fad-getad.c fad-gifc.c \
           fad-glifc.c fad-null.c fad-win32.c FILES gencode.c gencode.h \
           grammar.c grammar.y inet.c install-sh INSTALL.txt LICENSE \
           llc.h Makefile.in mkdep nametoaddr.c net nlpid.h \
           NMAP_MODIFICATIONS optimize.c pcap1.h pcap.3 pcap-bpf.c \
           pcap-bpf.h pcap.c pcap-dag.c pcap-dag.h pcap-dlpi.c pcap-dos.c \
           pcap-dos.h pcap-enet.c pcap.h pcap-int.h pcap-linux.c \
           pcap-namedb.h pcap-nit.c pcap-nit.h pcap-null.c pcap-pf.c \
           pcap-pf.h pcap-septel.c pcap-septel.h pcap-snit.c pcap-snoop.c \
           pcap-stdinc.h pcap-win32.c pf.h ppp.h README README.aix \
           README.dag README.hpux README.linux README.macosx README.septel \
           README.tru64 README.Win32 savefile.c scanner.c scanner.l sll.h \
           sunatmpos.h TODO tokdefs.h VERSION version.h \
           ChmodBPF/ChmodBPF ChmodBPF/StartupParameters.plist \
           doc/pcap.html doc/pcap.txt doc/pcap.xml lbl/os-aix4.h \
           lbl/os-hpux11.h lbl/os-osf4.h lbl/os-osf5.h lbl/os-solaris2.h \
           lbl/os-sunos4.h lbl/os-ultrix4.h missing/snprintf.c \
           msdos/bin2c.c msdos/common.dj msdos/makefile msdos/makefile.dj \
           msdos/makefile.wc msdos/ndis_0.asm msdos/ndis2.c msdos/ndis2.h \
           msdos/pktdrvr.c msdos/pktdrvr.h msdos/pkt_rx0.asm msdos/pkt_rx1.s \
           msdos/readme.dos SUNOS4/nit_if.o.sparc \
           SUNOS4/nit_if.o.sun3 SUNOS4/nit_if.o.sun4c.4.0.3c \
           bpf/net/bpf_filter.c Win32/Include/addrinfo.h \
           Win32/Include/bittypes.h Win32/Include/cdecl_ext.h \
           Win32/Include/Gnuc.h Win32/Include/inetprivate.h \
           Win32/Include/ip6_misc.h \
           Win32/Include/sockstorage.h Win32/Prj/libpcap.dsp \
           Win32/Prj/libpcap.dsw Win32/Src/ffs.c Win32/Src/getaddrinfo.c \
           Win32/Src/getnetbynm.c Win32/Src/getnetent.c Win32/Src/getopt.c \
           Win32/Src/getservent.c Win32/Src/inet_aton.c Win32/Src/inet_net.c \
           Win32/Src/inet_pton.c Win32/Include/arpa/nameser.h \
           Win32/Include/net/if.h Win32/Include/net/netdb.h \
           Win32/Include/net/paths.h \
           /usr/tmp/nmap-$(NMAP_VERSION)/$(LIBPCAPDIR)
	$(SHTOOL) mkdir /usr/tmp/nmap-$(NMAP_VERSION)/docs
	cd ../docs; cp -a README nmap_gpgkeys.txt \
                    nmap.usage.txt  \
                    nmap.1 nmapfe.1 xnmap.1 nmap.dtd nmap.xsl \
                    leet-nmap-ascii-art.txt \
                    $(wroot)/nmap/data/nmap-man.xml \
                    /usr/tmp/nmap-$(NMAP_VERSION)/docs
	$(SHTOOL) mkdir /usr/tmp/nmap-$(NMAP_VERSION)/nmapfe
	cd ../nmapfe; cp -a Makefile.in aclocal.m4 configure configure.ac \
	              nmapfe.c nmapfe.h nmapfe_sig.c nmapfe_sig.h \
	              nmapfe_error.c nmapfe_error.h NmapFE.dsp nmapfe.dsw \
	              /usr/tmp/nmap-$(NMAP_VERSION)/nmapfe

	$(SHTOOL) mkdir /usr/tmp/nmap-$(NMAP_VERSION)/nbase
	cd ../$(NBASEDIR); cp -a Makefile.in aclocal.m4 configlocal.m4 \
                        nbase.vcproj configure configure.ac nbase_config.h.in \
                        *.c *.h CHANGELOG /usr/tmp/nmap-$(NMAP_VERSION)/nbase

	$(SHTOOL) mkdir /usr/tmp/nmap-$(NMAP_VERSION)/libpcre
	cd ../libpcre; cp -a AUTHORS config.guess config.h.in config.sub \
               configure configure.ac dftables.c INSTALL install-sh \
               libpcre.vcproj LICENCE Makefile.in makevp.bat mkinstalldirs \
               NMAP_MODIFICATIONS NON-UNIX-USE pcre_chartables.c \
               pcre_compile.c pcre_config.c pcre_dfa_exec.c pcre_exec.c \
               pcre_fullinfo.c pcre_get.c pcre_globals.c pcre.h pcre.h.in \
               pcre_info.c pcre_internal.h pcre_maketables.c pcreposix.c \
               pcreposix.h pcre_printint.src pcre_refcount.c pcre_study.c \
               pcre_tables.c pcre_try_flipped.c pcre_version.c \
               pcre_winconfig.h pcre_xclass.c README ucp.h \
               /usr/tmp/nmap-$(NMAP_VERSION)/libpcre

	$(SHTOOL) mkdir /usr/tmp/nmap-$(NMAP_VERSION)/libdnet-stripped
	cd ../$(LIBDNETDIR); cp -a --parents acconfig.h aclocal.m4 \
            config/missing config/mkinstalldirs \
            config/acinclude.m4 config/install-sh \
            config/config.sub config/ltmain.sh config/config.guess \
            configure configure.in dnet-config.in include/dnet/rand.h \
            include/dnet/ip6.h include/dnet/ip.h include/dnet/route.h \
            include/dnet/icmp.h include/dnet/blob.h include/dnet/udp.h \
            include/dnet/os.h include/dnet/eth.h include/dnet/fw.h \
            include/dnet/intf.h include/dnet/Makefile.in include/dnet/tcp.h \
            include/dnet/arp.h include/dnet/Makefile.am include/dnet/tun.h \
            include/dnet/addr.h include/Makefile.in include/dnet.h \
            include/stamp-h1 include/dnet_winconfig.h include/Makefile.am \
            include/queue.h include/stamp-h.in include/config.h.in \
            include/err.h INSTALL libdnet-stripped.vcproj LICENSE \
            Makefile.am Makefile.am.common Makefile.in NMAP_MODIFICATIONS \
            README src/route-none.c src/ip-cooked.c \
            src/arp-win32.c src/ip-util.c src/route-win32.c src/fw-none.c \
            src/eth-linux.c src/route-bsd.c src/route-linux.c \
            src/tun-bsd.c src/strlcat.c src/tun-none.c src/memcmp.c \
            src/route-hpux.c src/addr-util.c src/eth-ndd.c src/ip6.c \
            src/intf.c src/Makefile.in src/addr.c src/eth-dlpi.c \
            src/rand.c src/tun-solaris.c src/intf-win32.c \
            src/eth-none.c src/ip.c src/ip-win32.c \
            src/arp-ioctl.c src/arp-none.c src/Makefile.am \
            src/eth-bsd.c src/strsep.c src/err.c src/strlcpy.c src/blob.c \
            src/eth-win32.c src/eth-snoop.c src/eth-pfilt.c src/tun-linux.c \
            src/arp-bsd.c THANKS TODO \
            /usr/tmp/nmap-$(NMAP_VERSION)/libdnet-stripped
	$(SHTOOL) mkdir /usr/tmp/nmap-$(NMAP_VERSION)/nsock
	$(SHTOOL) mkdir /usr/tmp/nmap-$(NMAP_VERSION)/nsock/include
	$(SHTOOL) mkdir /usr/tmp/nmap-$(NMAP_VERSION)/nsock/src
	cp ../nsock/nsock.vcproj /usr/tmp/nmap-$(NMAP_VERSION)/nsock/
	cd ../nsock; cp -a --parents  include/nsock.h nsock.vcproj \
           src/nsock_utils.c src/aclocal.m4 src/error.h src/netutils.c \
           src/gh_list.h src/nsock_internal.h src/nsock_write.c \
           src/nsock_core.c src/nsock_pool.c src/configure src/Makefile.in \
           src/filespace.h src/nsock_utils.h src/install-sh src/config.sub \
           src/nsock_timers.c src/nsock_read.c src/nsock_iod.c \
           src/nsock_ssl.c src/config.guess src/filespace.c src/nsock_ssl.h \
           src/configure.ac src/nsock_config.h.in src/nsock_connect.c \
           src/nsock_event.c src/gh_list.c src/error.c src/netutils.h TODO \
           /usr/tmp/nmap-$(NMAP_VERSION)/nsock/

	rm -f /usr/tmp/nmap-$(NMAP_VERSION)/nbase/nbase_config.h 
# Kill the SVN/CVS crap
	find /usr/tmp/nmap-$(NMAP_VERSION) -type d -name CVS | xargs rm -rf
	find /usr/tmp/nmap-$(NMAP_VERSION) -type d -name .svn | xargs rm -rf
	find /usr/tmp/nmap-$(NMAP_VERSION) -exec chmod go=u-w '{}' \;
	cd /usr/tmp; tar cjf nmap-$(NMAP_VERSION).tar.bz2 nmap-$(NMAP_VERSION)
	cd /usr/tmp; tar czf nmap-$(NMAP_VERSION).tgz nmap-$(NMAP_VERSION)
# Make the actual RPM
#	rpmbuild -ta --define "buildfe 0" --define "static 1" /usr/tmp/nmap-$(NMAP_VERSION).tgz
	rpmbuild -ta --define "static 1" /usr/tmp/nmap-$(NMAP_VERSION).tgz
	cp -f $(RPMTDIR)/RPMS/x86_64/nmap-$(NMAP_VERSION)-1.x86_64.rpm /usr/tmp
#	cp -f $(RPMTDIR)/RPMS/i386/nmap-$(NMAP_VERSION)-1.i386.rpm /usr/tmp
	cp -f $(RPMTDIR)/RPMS/x86_64/nmap-frontend-$(NMAP_VERSION)-1.x86_64.rpm /usr/tmp
	cp -f $(RPMTDIR)/SRPMS/nmap-$(NMAP_VERSION)-1.src.rpm /usr/tmp
	rm -rf /usr/tmp/nmap-$(NMAP_VERSION)
