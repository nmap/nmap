MAKENSIS="/cygdrive/c/Program Files/NSIS/makensis.exe"
VCEXPRESS := $(shell reg query "HKEY_CLASSES_ROOT\\Applications\\VCExpress.exe\\shell\\edit\\command" | egrep -i '[A-H]:\\' | cut -d\" -f2 | sed 's%\\%/%g' | tr -d '\n')
export NMAP_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NMAP_VERSION' ../nmap.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
export NMAP_NUM_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NMAP_NUM_VERSION' ../nmap.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
COMMA_VERSION=$(shell echo $(NMAP_NUM_VERSION) | tr '.' ',')
LOGLOC=c:nmapbuild.log
NSE_FILES = scripts/script.db scripts/*.nse
NMAP_MSWIN32_AUX = ../../nmap-mswin32-aux

winbuild: nmap.rc nsis/Nmap.nsi LICENSE
# VCExpress.exe is devenv.com with the commercial Visual Studio suite instead of VC++ Express

	"$(VCEXPRESS)" nmap.sln /build release /out $(LOGLOC)
	"$(VCEXPRESS)" nmap.sln /build release /project nmap-update /out $(LOGLOC)
	$(MAKENSIS) winpcap/winpcap-nmap.nsi
	rm -rf nmap-$(NMAP_VERSION)
	rm -f nmap-$(NMAP_VERSION)-win32.zip
	mkdir nmap-$(NMAP_VERSION)
	cd Release && cp -r ../../CHANGELOG ../../COPYING nmap-mac-prefixes nmap-os-db nmap-payloads nmap-protocols nmap-rpc nmap-service-probes nmap-services nmap.exe nmap.xsl nse_main.lua ../nmap_performance.reg ../../README-WIN32 ../../docs/3rd-party-licenses.txt ../nmap-$(NMAP_VERSION)/
# Use "cmd /c copy" rather than "cp" to preserve Windows ACLs. Using
# "cp" means that the copied DLLs don't have the same ACL and cause an
# error on startup: 0xc0000022.
	cmd /c copy $(subst /,\\,$(NMAP_MSWIN32_AUX))\\OpenSSL\\bin\\*.dll nmap-$(NMAP_VERSION)
	mkdir nmap-$(NMAP_VERSION)/scripts
	cd Release && cp -f $(NSE_FILES) ../nmap-$(NMAP_VERSION)/scripts/
	cd Release && for f in `find nselib -name .svn -prune -o -type d -print`; do \
		mkdir -p ../nmap-$(NMAP_VERSION)/$$f; \
	done
	cd Release && for f in `find nselib -name .svn -prune -o -type f -print`; do \
		cp -f $$f ../nmap-$(NMAP_VERSION)/$$f; \
	done
	cd Release && cp -r ../../docs/licenses ../nmap-$(NMAP_VERSION)/
	rm -rf nmap-$(NMAP_VERSION)/licenses/.svn
	cp winpcap/winpcap-nmap-*.exe nmap-$(NMAP_VERSION)
	cp $(NMAP_MSWIN32_AUX)/vcredist_x86.exe nmap-$(NMAP_VERSION)
	cp $(NMAP_MSWIN32_AUX)/vcredist2008_x86.exe nmap-$(NMAP_VERSION)
	cp ../ncat/Release/ncat.exe nmap-$(NMAP_VERSION)
	cp ../ncat/Release/ca-bundle.crt nmap-$(NMAP_VERSION)
	cp ../nping/Release/nping.exe nmap-$(NMAP_VERSION)
	cp ../nmap-update/Release/nmap-update.exe nmap-$(NMAP_VERSION)
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

nmap.rc: nmap.rc.in
	sed -e '1i// Automatically generated from $<.' \
	     -e 's/@@FILEVERSION@@/"$(NMAP_VERSION)\\0"/' \
	     -e 's/@@COMMAVERSION@@/$(COMMA_VERSION)/' \
	     "$<" > "$@"

nsis/Nmap.nsi: nsis/Nmap.nsi.in
	sed -e '1i; Automatically generated from $<.' \
	     -e 's/@@VIPRODUCTVERSION@@/"$(NMAP_NUM_VERSION)"/' \
	     -e 's/@@VERSION@@/"$(NMAP_VERSION)"/' \
	     "$<" > "$@"

LICENSE: ../COPYING
	./license-format/licformat.sh "$<" > "$@"

clean:
	"$(VCEXPRESS)" nmap.sln /clean
	rm -rf Debug Release nmapbuild.log nmap.rc nsis/Nmap.nsi LICENSE
