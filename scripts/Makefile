
CC=gcc
CPP=g++
INCLUDE_FLAGS= -I.. -I../nbase -I../libpcap-possiblymodified
LINK_FLAGS=-L.. -L../nbase -L../libpcap-possiblymodified
NMAP_OBJS=../osscan.o ../nmap_error.o ../utils.o ../tcpip.o ../output.o ../nmap.o ../scan_engine.o ../portlist.o ../timing.o ../nmap_rpc.o ../charpool.o ../services.o ../targets.o ../idle_scan.o ../protocols.o ../FingerPrintResults.o ../NmapOps.o ../TargetGroup.o ../Target.o ../NmapOutputTable.o ../service_scan.o ../nsock/src/libnsock.a
DEFINES=-DHAVE_CONFIG_H=1

all: fingermatch fingerdiff servicematch

dummy:

fingermatch: dummy
	$(CPP) -g -Wall $(INCLUDE_FLAGS) $(LINK_FLAGS) $(DEFINES) -o $@ $@.cc $(NMAP_OBJS) -lm -lnbase -lpcap -lpcre -lssl -lcrypt

fingerdiff: dummy
	$(CPP) -g -Wall $(INCLUDE_FLAGS) $(LINK_FLAGS) $(DEFINES) -o $@ $@.cc $(NMAP_OBJS) -lm -lnbase -lpcap -lpcre -lssl -lcrypt

servicematch: dummy
	$(CPP) -g -Wall $(INCLUDE_FLAGS) $(LINK_FLAGS) $(DEFINES) -o $@ $@.cc $(NMAP_OBJS) -lm -lnbase -lpcap -lpcre -lssl -lcrypt

web:
	test x$(wroot) != x
	cd .. && cp -a CHANGELOG HACKING COPYING COPYING.OpenSSL INSTALL $(DATAFILES) README-WIN32 mswin32/nmap_performance.reg $(wroot)/nmap/data
	cd ../docs && cp -a nmap_manpage*.html nmap*.1 xnmap.1 nmap.usage.txt nmap.dtd nmap.xsl $(wroot)/nmap/data/
	./sort-prints.pl ../nmap-os-fingerprints > nos && mv nos ../nmap-os-fingerprints
	./produceosclasschoosebox.pl ../nmap-os-fingerprints > $(wroot)/nmap/data/os-classes.txt
	./sign_release.pl $(wroot)/nmap/dist
	find $(wroot)/nmap/data/ -type f -exec chmod 644 '{}' \;
	find $(wroot)/nmap/dist/sigs -type f -exec chmod 644 '{}' \;