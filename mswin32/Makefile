MAKENSIS=/c/apps/NSIS/makensis.exe
VCEXPRESS="/c/Program Files/Microsoft Visual Studio 8/Common7/IDE/VCExpress.exe"
export NMAP_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NMAP_VERSION' ../nmap.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
LOGLOC=c:nmapbuild.log
NSE_FILES = scripts/script.db scripts/*.nse

winbuild:
# VCExpress.exe is devenv.com with the commercial Visual Studio suite instead of VC++ Express
	$(VCEXPRESS) nmap.sln /build release /log $(LOGLOC)
	$(MAKENSIS) winpcap/winpcap-nmap.nsi
	rm -rf nmap-$(NMAP_VERSION)
	mkdir nmap-$(NMAP_VERSION)
	cd Release && cp -r ../../CHANGELOG ../../COPYING nmap-mac-prefixes nmap-os-fingerprints nmap-os-db nmap-protocols nmap-rpc nmap-service-probes nmap-services nmap.exe nmap.xsl ../nmap_performance.reg ../../README-WIN32 ../nmap-$(NMAP_VERSION)/
	mkdir nmap-$(NMAP_VERSION)/scripts
	cd Release && cp -f $(NSE_FILES) ../nmap-$(NMAP_VERSION)/scripts/
	zip -r nmap-$(NMAP_VERSION)-win32.zip nmap-$(NMAP_VERSION)
	cp winpcap/winpcap-nmap-*.exe nmap-$(NMAP_VERSION)
	cp nsis/AddToPath.nsh nsis/Nmap.nsi nmap-$(NMAP_VERSION)
	$(MAKENSIS) nmap-$(NMAP_VERSION)/Nmap.nsi
	mv nmap-$(NMAP_VERSION)/NmapInstaller.exe nmap-$(NMAP_VERSION)-setup.exe

clean:
	$(VCEXPRESS) nmap.sln /clean
	rm -rf Debug Release nmapbuild.log
