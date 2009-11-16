MAKENSIS="/cygdrive/c/Program Files/NSIS/makensis.exe"
VCEXPRESS := $(shell reg query "HKEY_CLASSES_ROOT\\Applications\\VCExpress.exe\\shell\\edit\\command" | egrep '[A-H]:\\' | cut -d\" -f2 | sed 's%\\%/%g' | tr -d '\n')
export NMAP_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NMAP_VERSION' ../nmap.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
export NMAP_NUM_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NMAP_NUM_VERSION' ../nmap.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
COMMA_VERSION=$(shell echo $(NMAP_NUM_VERSION) | tr '.' ',')
LOGLOC=c:nmapbuild.log
NSE_FILES = scripts/script.db scripts/*.nse

winbuild:
# VCExpress.exe is devenv.com with the commercial Visual Studio suite instead of VC++ Express

	@echo "Setting version: $(NMAP_VERSION) ($(NMAP_NUM_VERSION))"
	@cat ./nmap.rc | sed 's/VALUE "FileVersion", .*"/VALUE "FileVersion", "$(NMAP_VERSION)\\0"/' > ./nmap.rc.tmp
	@cat ./nmap.rc.tmp | sed 's/FILEVERSION .*,.*,.*,.*/FILEVERSION $(COMMA_VERSION)/' > ./nmap.rc
	@cat ./nsis/Nmap.nsi | sed 's/VIProductVersion ".*"/VIProductVersion "$(NMAP_NUM_VERSION)"/' > ./nmap.nsi.tmp
	@cat ./nmap.nsi.tmp | sed 's/!define VERSION ".*"/!define VERSION "$(NMAP_VERSION)"/' > ./nsis/Nmap.nsi
	@rm ./nmap.nsi.tmp ./nmap.rc.tmp
	@./license-format/licformat.sh ../COPYING > LICENSE

	"$(VCEXPRESS)" nmap.sln /build release /log $(LOGLOC)
	$(MAKENSIS) winpcap/winpcap-nmap.nsi
	rm -rf nmap-$(NMAP_VERSION)
	rm -f nmap-$(NMAP_VERSION)-win32.zip
	mkdir nmap-$(NMAP_VERSION)
	cd Release && cp -r ../../CHANGELOG ../../COPYING nmap-mac-prefixes nmap-os-db nmap-protocols nmap-rpc nmap-service-probes nmap-services nmap.exe nmap.xsl nse_main.lua ../nmap_performance.reg ../../README-WIN32 ../nmap-$(NMAP_VERSION)/
	cp -f OpenSSL/bin/*.dll ./nmap-$(NMAP_VERSION)/
	mkdir nmap-$(NMAP_VERSION)/scripts
	cd Release && cp -f $(NSE_FILES) ../nmap-$(NMAP_VERSION)/scripts/
	mkdir nmap-$(NMAP_VERSION)/nselib
	cp -a Release/nselib nmap-$(NMAP_VERSION)
	cp winpcap/winpcap-nmap-*.exe nmap-$(NMAP_VERSION)
	cp vcredist_x86.exe nmap-$(NMAP_VERSION)
	cp ../ncat/Release/ncat.exe nmap-$(NMAP_VERSION)
	cp ../ncat/Release/ca-bundle.crt nmap-$(NMAP_VERSION)
# Install the ndiff batch file wrapper in the zip distribution.
	cp ../ndiff/ndiff nmap-$(NMAP_VERSION)/ndiff.py
	cp python-wrap.bat nmap-$(NMAP_VERSION)/ndiff.bat
	zip -r nmap-$(NMAP_VERSION)-win32.zip nmap-$(NMAP_VERSION)
# Remove ndiff.py and ndiff.bat for the installer because it has ndiff.exe.
	rm -f nmap-$(NMAP_VERSION)/ndiff.py nmap-$(NMAP_VERSION)/ndiff.bat
	cd ../zenmap && install_scripts/windows/copy_and_compile.bat
	cp -R ../zenmap/dist/* nmap-$(NMAP_VERSION)/
	cp ../zenmap/README nmap-$(NMAP_VERSION)/ZENMAP_README
	cp ../zenmap/COPYING_HIGWIDGETS nmap-$(NMAP_VERSION)
	cp ../ndiff/README nmap-$(NMAP_VERSION)/NDIFF_README
	cp nsis/AddToPath.nsh nsis/Nmap.nsi nsis/shortcuts.ini nsis/final.ini nmap-$(NMAP_VERSION)
	$(MAKENSIS) nmap-$(NMAP_VERSION)/Nmap.nsi
	mv nmap-$(NMAP_VERSION)/NmapInstaller.exe nmap-$(NMAP_VERSION)-setup.exe

clean:
	$(VCEXPRESS) nmap.sln /clean
	rm -rf Debug Release nmapbuild.log
