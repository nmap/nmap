MAKENSIS="/cygdrive/c/Program Files/NSIS/makensis.exe"
# VCExpress.exe is devenv.com with the commercial Visual Studio suite instead of VC++ Express
VCEXPRESS := $(shell reg query "HKEY_CLASSES_ROOT\\Applications\\devenv.exe\\shell\\edit\\command" | egrep -i '[A-Z]:\\' | cut -d\" -f2 | sed 's%\\%/%g' | tr -d '\r\n')
SIGNTOOL := $(shell reg query "HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Microsoft SDKs\\Windows\\v8.1" /v "InstallationFolder" | egrep InstallationFolder | cut -d ' ' -f13- | sed 's%\\%/%g' | tr -d '\r\n' | sed 's%$$%bin/x86/signtool.exe%')
export NMAP_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NMAP_VERSION' ../nmap.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
export NMAP_NUM_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NMAP_NUM_VERSION' ../nmap.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
export NPCAP_VERSION := $(shell ls npcap-*.exe | sed -e 's/npcap-\([-r0-9.]*\)\.exe/\1/' -e 'q')
COMMA_VERSION=$(shell echo $(NMAP_NUM_VERSION) | tr '.' ',')
LOGLOC=c:nmapbuild.log
NSE_FILES = scripts/script.db scripts/*.nse
NMAP_MSWIN32_AUX = ../../nmap-mswin32-aux
SIGNTOOL_ARGS = sign /a /n "Insecure.Com LLC" /tr http://timestamp.digicert.com /td sha256 /fd sha256
# escape quotes for NSIS
# escape for right side of sed regex replace
SIGNTOOL_SUBST = $(shell echo '"$(SIGNTOOL)" $(SIGNTOOL_ARGS)' | sed -e 's/"/$$\\"/g' -e 's/[\/&]/\\&/g' )

bundle-nmap: bundle-zip bundle-nsis

build-nmap: nmap.sln nmap.rc
	"$(VCEXPRESS)" nmap.sln /build release /out $(LOGLOC)
	"$(VCEXPRESS)" nmap.sln /build release /project nmap-update /out $(LOGLOC)

stage-nmap: build-nmap LICENSE
	rm -rf nmap-$(NMAP_VERSION)
	mkdir nmap-$(NMAP_VERSION)
	cd Release && cp -r ../../CHANGELOG ../../COPYING nmap-mac-prefixes nmap-os-db nmap-payloads nmap-protocols nmap-rpc nmap-service-probes nmap-services nmap.exe nmap.xsl nse_main.lua ../nmap_performance.reg ../../README-WIN32 ../../docs/3rd-party-licenses.txt ../nmap-$(NMAP_VERSION)/
# Use "cmd /c copy" rather than "cp" to preserve Windows ACLs. Using
# "cp" means that the copied DLLs don't have the same ACL and cause an
# error on startup: 0xc0000022.
	cmd /c copy $(subst /,\\,$(NMAP_MSWIN32_AUX))\\OpenSSL\\bin\\*.dll nmap-$(NMAP_VERSION)
	cmd /c copy Release\\libssh2.dll nmap-$(NMAP_VERSION)
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
	cp npcap-$(NPCAP_VERSION).exe nmap-$(NMAP_VERSION)
	cp $(NMAP_MSWIN32_AUX)/vcredist_x86.exe nmap-$(NMAP_VERSION)
	cp $(NMAP_MSWIN32_AUX)/vcredist2008_x86.exe nmap-$(NMAP_VERSION)
	cp ../ncat/Release/ncat.exe nmap-$(NMAP_VERSION)
	cp ../ncat/Release/ca-bundle.crt nmap-$(NMAP_VERSION)
	cp ../nping/Release/nping.exe nmap-$(NMAP_VERSION)
	cp ../nmap-update/Release/nmap-update.exe nmap-$(NMAP_VERSION)
# Install the ndiff batch file wrapper in the zip distribution.
	cp ../ndiff/ndiff.py nmap-$(NMAP_VERSION)/ndiff.py
	cp python-wrap.bat nmap-$(NMAP_VERSION)/ndiff.bat
	cd ../zenmap && install_scripts/windows/copy_and_compile.bat
	cp -R ../zenmap/dist/* nmap-$(NMAP_VERSION)/
	cp ../zenmap/README nmap-$(NMAP_VERSION)/ZENMAP_README
	cp ../zenmap/COPYING_HIGWIDGETS nmap-$(NMAP_VERSION)
	cp ../ndiff/README nmap-$(NMAP_VERSION)/NDIFF_README

sign-files: nmap-$(NMAP_VERSION)/nmap.exe nmap-$(NMAP_VERSION)/ncat.exe nmap-$(NMAP_VERSION)/nping.exe nmap-$(NMAP_VERSION)/nmap-update.exe nmap-$(NMAP_VERSION)/ndiff.exe nmap-$(NMAP_VERSION)/zenmap.exe nmap-$(NMAP_VERSION)/libssh2.dll nmap-$(NMAP_VERSION)/libeay32.dll nmap-$(NMAP_VERSION)/ssleay32.dll
	# TODO: evaluate whether we should also sign the Python stuff for Zenmap, Ndiff
	"$(SIGNTOOL)" $(SIGNTOOL_ARGS) $^

bundle-nsis: nsis/Nmap.nsi sign-files
	cp nsis/AddToPath.nsh nsis/Nmap.nsi nsis/shortcuts.ini nsis/final.ini nmap-$(NMAP_VERSION)
	$(MAKENSIS) nmap-$(NMAP_VERSION)/Nmap.nsi
	mv nmap-$(NMAP_VERSION)/NmapInstaller.exe nmap-$(NMAP_VERSION)-setup.exe
	"$(SIGNTOOL)" $(SIGNTOOL_ARGS) nmap-$(NMAP_VERSION)-setup.exe

bundle-zip: sign-files
	rm -f nmap-$(NMAP_VERSION)-win32.zip
	zip -x nmap-$(NMAP_VERSION)/ZENMAP_README nmap-$(NMAP_VERSION)/zenmap/\* \
	  nmap-$(NMAP_VERSION)/zenmap.exe nmap-$(NMAP_VERSION)/share/\* \
	  nmap-$(NMAP_VERSION)/python27.dll nmap-$(NMAP_VERSION)/py2exe/\* \
	  nmap-$(NMAP_VERSION)/COPYING_HIGWIDGETS nmap-$(NMAP_VERSION)/w9xpopen.exe \
	  nmap-$(NMAP_VERSION)/ndiff.exe nmap-$(NMAP_VERSION)/\*.ini \
	  nmap-$(NMAP_VERSION)/Uninstall.exe nmap-$(NMAP_VERSION)/\*.nsi \
	  nmap-$(NMAP_VERSION)/\*.nsh \
	  -r nmap-$(NMAP_VERSION)-win32.zip nmap-$(NMAP_VERSION)

nmap.rc: nmap.rc.in ../nmap.h
	sed -e '1i// Automatically generated from $<.' \
	     -e 's/@@FILEVERSION@@/"$(NMAP_VERSION)\\0"/' \
	     -e 's/@@COMMAVERSION@@/$(COMMA_VERSION)/' \
	     "$<" > "$@"

nsis/Nmap.nsi: nsis/Nmap.nsi.in ../nmap.h
	test -n "$(NPCAP_VERSION)" # Make sure NPcap is present
	sed -e '1i; Automatically generated from $<.' \
	     -e 's/@@VIPRODUCTVERSION@@/"$(NMAP_NUM_VERSION)"/' \
	     -e 's/@@VERSION@@/"$(NMAP_VERSION)"/' \
	     -e 's/@@NPCAP_VERSION@@/$(NPCAP_VERSION)/' \
	     -e 's/@@SIGNTOOL@@/$(SIGNTOOL_SUBST)/' \
	     "$<" > "$@"

LICENSE: ../COPYING
	./license-format/licformat.sh "$<" > "$@"

clean:
	"$(VCEXPRESS)" nmap.sln /clean
	rm -rf Debug Release nmapbuild.log nmap.rc nsis/Nmap.nsi LICENSE
