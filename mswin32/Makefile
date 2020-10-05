MAKENSIS=/cygdrive/c/Program Files (x86)/NSIS-strlen/makensis.exe
MAKENSIS_WIN=$(shell echo '$(MAKENSIS)' | sed 's|/cygdrive/\(.\)|\1:|;s|/|\\|g')
# VCExpress.exe is devenv.com with the commercial Visual Studio suite instead of VC++ Express
VCEXPRESS := $(shell reg query "HKEY_CLASSES_ROOT\\Applications\\devenv.exe\\shell\\edit\\command" | egrep -i '[A-Z]:\\' | cut -d\" -f2 | sed 's%\\%/%g' | tr -d '\r\n')
SIGNTOOL := $(shell reg query "HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Microsoft SDKs\\Windows\\v8.1" /v "InstallationFolder" | egrep InstallationFolder | cut -d ' ' -f13- | sed 's%\\%/%g' | tr -d '\r\n' | sed 's%$$%bin/x86/signtool.exe%')
NMAPDIR=..
NMAPDIR_WIN=$(shell echo '$(NMAPDIR)' | sed 's|/cygdrive/\(.\)|\1:|;s|/|\\|g')
export NMAP_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NMAP_VERSION' $(NMAPDIR)/nmap.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
export NMAP_NUM_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NMAP_NUM_VERSION' $(NMAPDIR)/nmap.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
export NPCAP_VERSION := $(shell ls npcap-*.exe | sed -e 's/npcap-\([0-9.]*\)[-oem]*\.exe/\1/' -e 'q')
COMMA_VERSION=$(shell echo $(NMAP_NUM_VERSION) | tr '.' ',')
LOGLOC=c:nmapbuild.log
NSE_FILES = $(NMAPDIR)/scripts/script.db $(NMAPDIR)/scripts/*.nse
NMAP_MSWIN32_AUX = $(NMAPDIR)/../nmap-mswin32-aux
SIGNTOOL_ARGS = sign /a /n "Insecure.Com LLC" /tr http://timestamp.digicert.com /td sha256 /fd sha256
# escape quotes for NSIS
# escape for right side of sed regex replace
SIGNTOOL_SUBST = $(shell echo '"$(SIGNTOOL)" $(SIGNTOOL_ARGS)' | sed -e 's/"/$$\\"/g' -e 's/[\/&]/\\&/g' )

PRODUCT_NAME=Nmap
PLATFORM=Win32
VCCONFIG=Release
NSIS_DEFINES=

bundle-nmap: bundle-zip bundle-nsis

build-nmap${OEM_SUFFIX}: nmap.sln nmap${OEM_SUFFIX}.rc
	"$(VCEXPRESS)" nmap.sln /build "$(VCCONFIG)${OEM_SUFFIX}|$(PLATFORM)" /out $(LOGLOC)

stage-common: $(NMAPDIR)/CHANGELOG $(NMAPDIR)/LICENSE $(NMAPDIR)/nmap-mac-prefixes $(NMAPDIR)/nmap-os-db $(NMAPDIR)/nmap-payloads $(NMAPDIR)/nmap-protocols $(NMAPDIR)/nmap-rpc $(NMAPDIR)/nmap-service-probes $(NMAPDIR)/nmap-services $(NMAPDIR)/docs/nmap.xsl $(NMAPDIR)/nse_main.lua $(NMAPDIR)/mswin32/nmap_performance.reg $(NMAPDIR)/README-WIN32 $(NMAPDIR)/docs/3rd-party-licenses.txt icon1.ico LICENSE.formatted
	mkdir -p nmap-$(NMAP_VERSION)
	cp $^ nmap-$(NMAP_VERSION)/
# Use "cmd /c copy" rather than "cp" to preserve Windows ACLs. Using
# "cp" means that the copied DLLs don't have the same ACL and cause an
# error on startup: 0xc0000022.
	cmd /c copy $(subst /,\\,$(NMAP_MSWIN32_AUX))\\OpenSSL\\bin\\*.dll nmap-$(NMAP_VERSION)
	cmd /c copy $(NMAPDIR_WIN)\\libssh2\\win32\\$(VCCONFIG)_dll\\libssh2.dll nmap-$(NMAP_VERSION)
	cmd /c copy $(NMAPDIR_WIN)\\libz\\contrib\\vstudio\\vc12\\x86\\ZlibDll$(VCCONFIG)WithoutAsm\\zlibwapi.dll nmap-$(NMAP_VERSION)
	mkdir -p nmap-$(NMAP_VERSION)/scripts
	cp -f $(NSE_FILES) nmap-$(NMAP_VERSION)/scripts/
	for f in `cd $(NMAPDIR) && find nselib -name .svn -prune -o -type d -print`; do \
		mkdir -p nmap-$(NMAP_VERSION)/$$f; \
	done
	for f in `cd $(NMAPDIR) && find nselib -name .svn -prune -o -type f -print`; do \
		cp -f $(NMAPDIR)/$$f nmap-$(NMAP_VERSION)/$$f; \
	done
	cp -r $(NMAPDIR)/docs/licenses nmap-$(NMAP_VERSION)/
	rm -rf nmap-$(NMAP_VERSION)/licenses/.svn
	cp $(NMAP_MSWIN32_AUX)/vcredist_x86.exe nmap-$(NMAP_VERSION)
	cp $(NMAP_MSWIN32_AUX)/vcredist2008_x86.exe nmap-$(NMAP_VERSION)
	cp $(NMAPDIR)/ncat/$(VCCONFIG)/ncat.exe nmap-$(NMAP_VERSION)
	cp $(NMAPDIR)/ncat/$(VCCONFIG)/ca-bundle.crt nmap-$(NMAP_VERSION)
	cp $(NMAPDIR)/nping/$(VCCONFIG)/nping.exe nmap-$(NMAP_VERSION)
# Install the ndiff batch file wrapper in the zip distribution.
	cp $(NMAPDIR)/ndiff/ndiff.py nmap-$(NMAP_VERSION)/ndiff.py
	cp python-wrap.bat nmap-$(NMAP_VERSION)/ndiff.bat
	cd $(NMAPDIR)/zenmap && install_scripts/windows/copy_and_compile.bat
	cp -R $(NMAPDIR)/zenmap/dist/* nmap-$(NMAP_VERSION)/
	cp $(NMAPDIR)/zenmap/README nmap-$(NMAP_VERSION)/ZENMAP_README
	cp $(NMAPDIR)/zenmap/COPYING_HIGWIDGETS nmap-$(NMAP_VERSION)
	cp $(NMAPDIR)/ndiff/README nmap-$(NMAP_VERSION)/NDIFF_README
	cp nsis/AddToPath.nsh nsis/shortcuts.ini nsis/final.ini nmap-$(NMAP_VERSION)

stage: stage-nmap stage-nmap-oem stage-common

stage-nmap:
	$(MAKE)	OEM_SUFFIX= stage-nmap-main

stage-nmap-oem:
	$(MAKE)	OEM_SUFFIX=-oem stage-nmap-main

stage-nmap-main: nmap-$(NMAP_VERSION)/Nmap.nsi build-nmap${OEM_SUFFIX}
	mkdir -p nmap-$(NMAP_VERSION)${OEM_SUFFIX}
	cp $(VCCONFIG)${OEM_SUFFIX}/nmap.exe nmap-$(NMAP_VERSION)${OEM_SUFFIX}/

sign-files: nmap-$(NMAP_VERSION)-oem/nmap.exe nmap-$(NMAP_VERSION)/nmap.exe nmap-$(NMAP_VERSION)/ncat.exe nmap-$(NMAP_VERSION)/nping.exe nmap-$(NMAP_VERSION)/ndiff.exe nmap-$(NMAP_VERSION)/zenmap.exe nmap-$(NMAP_VERSION)/libssh2.dll nmap-$(NMAP_VERSION)/libcrypto-1_1.dll nmap-$(NMAP_VERSION)/libssl-1_1.dll nmap-$(NMAP_VERSION)/zlibwapi.dll
	# TODO: evaluate whether we should also sign the Python stuff for Zenmap, Ndiff
	"$(SIGNTOOL)" $(SIGNTOOL_ARGS) $^
	touch sign-files

bundle-nsis: sign-files
	"$(MAKENSIS)" "/XOutFile nmap-$(NMAP_VERSION)-setup.exe" "/DNSISEXE=$(MAKENSIS_WIN)" nmap-$(NMAP_VERSION)/Nmap.nsi
	mv nmap-$(NMAP_VERSION)/nmap-$(NMAP_VERSION)-setup.exe .
	"$(MAKENSIS)" "/XOutFile nmap-$(NMAP_VERSION)-oem-setup.exe" "/DNSISEXE=$(MAKENSIS_WIN)" "/DNMAP_OEM=1" nmap-$(NMAP_VERSION)/Nmap.nsi
	mv nmap-$(NMAP_VERSION)/nmap-$(NMAP_VERSION)-oem-setup.exe .
	"$(SIGNTOOL)" $(SIGNTOOL_ARGS) nmap-$(NMAP_VERSION)-setup.exe nmap-$(NMAP_VERSION)-oem-setup.exe

bundle-zip: bundle-zip-public bundle-zip-oem

bundle-zip-public:
	$(MAKE) OEM_SUFFIX= bundle-zip-main

bundle-zip-oem:
	$(MAKE) OEM_SUFFIX=-oem bundle-zip-main

bundle-zip-main: sign-files
	rm -f nmap-$(NMAP_VERSION)${OEM_SUFFIX}-win32.zip
	test -n "${OEM_SUFFIX}" \
	       && cp -n -R nmap-$(NMAP_VERSION)/* nmap-$(NMAP_VERSION)${OEM_SUFFIX}/ \
	       || true
	cp npcap-$(NPCAP_VERSION)${OEM_SUFFIX}.exe nmap-$(NMAP_VERSION)${OEM_SUFFIX}
	zip -x nmap-$(NMAP_VERSION)${OEM_SUFFIX}/ZENMAP_README \
	  nmap-$(NMAP_VERSION)${OEM_SUFFIX}/zenmap/\* \
	  nmap-$(NMAP_VERSION)${OEM_SUFFIX}/zenmap.exe \
	  nmap-$(NMAP_VERSION)${OEM_SUFFIX}/share/\* \
	  nmap-$(NMAP_VERSION)${OEM_SUFFIX}/python27.dll \
	  nmap-$(NMAP_VERSION)${OEM_SUFFIX}/py2exe/\* \
	  nmap-$(NMAP_VERSION)${OEM_SUFFIX}/COPYING_HIGWIDGETS \
	  nmap-$(NMAP_VERSION)${OEM_SUFFIX}/w9xpopen.exe \
	  nmap-$(NMAP_VERSION)${OEM_SUFFIX}/vcredist2008_x86.exe \
	  nmap-$(NMAP_VERSION)${OEM_SUFFIX}/ndiff.exe \
	  nmap-$(NMAP_VERSION)${OEM_SUFFIX}/\*.ini \
	  nmap-$(NMAP_VERSION)${OEM_SUFFIX}/Uninstall.exe \
	  nmap-$(NMAP_VERSION)${OEM_SUFFIX}/\*.nsi \
	  nmap-$(NMAP_VERSION)${OEM_SUFFIX}/\*.nsh \
	  nmap-$(NMAP_VERSION)${OEM_SUFFIX}/LICENSE.formatted \
	  nmap-$(NMAP_VERSION)${OEM_SUFFIX}/icon1.ico \
	  -r nmap-$(NMAP_VERSION)${OEM_SUFFIX}-win32.zip nmap-$(NMAP_VERSION)${OEM_SUFFIX}
	rm nmap-$(NMAP_VERSION)${OEM_SUFFIX}/npcap-$(NPCAP_VERSION)${OEM_SUFFIX}.exe

nmap.rc: nmap.rc.in $(NMAPDIR)/nmap.h
	sed -e '1i// Automatically generated from $<.' \
	     -e 's/@@FILEVERSION@@/"$(NMAP_VERSION)\\0"/' \
	     -e 's/@@COMMAVERSION@@/$(COMMA_VERSION)/' \
	     -e 's/@@PRODUCT_NAME@@/$(PRODUCT_NAME)/' \
	     "$<" > "$@"

nmap-oem.rc: nmap.rc.in $(NMAPDIR)/nmap.h
	sed -e '1i// Automatically generated from $<.' \
	     -e 's/@@FILEVERSION@@/"$(NMAP_VERSION)\\0"/' \
	     -e 's/@@COMMAVERSION@@/$(COMMA_VERSION)/' \
	     -e 's/@@PRODUCT_NAME@@/$(PRODUCT_NAME) OEM/' \
	     "$<" > "$@"

nmap-$(NMAP_VERSION)/Nmap.nsi: nsis/Nmap.nsi.in $(NMAPDIR)/nmap.h
	test -n "$(NPCAP_VERSION)" # Make sure NPcap is present
	mkdir -p nmap-$(NMAP_VERSION)
	sed -e '1i; Automatically generated from $<.' \
	     -e 's/@@VIPRODUCTVERSION@@/"$(NMAP_NUM_VERSION)"/' \
	     -e 's/@@VERSION@@/"$(NMAP_VERSION)"/' \
	     -e 's/@@NPCAP_VERSION@@/$(NPCAP_VERSION)/' \
	     -e 's/@@SIGNTOOL@@/$(SIGNTOOL_SUBST)/' \
	     -e 's/@@PRODUCT_NAME@@/$(PRODUCT_NAME)/' \
	     "$<" > "$@"

LICENSE.formatted: $(NMAPDIR)/LICENSE
	./license-format/licformat.sh "$<" > "$@"

clean:
	"$(VCEXPRESS)" nmap.sln /clean
	rm -rf nmap-$(NMAP_VERSION) nmap-$(NMAP_VERSION)-oem Debug Release Release-oem nmapbuild.log nmap.rc nmap-oem.rc LICENSE.formatted
