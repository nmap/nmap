MAKENSIS="/cygdrive/c/Program Files (x86)/NSIS/makensis.exe"
# VCExpress.exe is devenv.com with the commercial Visual Studio suite instead of VC++ Express
VCEXPRESS := $(shell reg query "HKEY_CLASSES_ROOT\\Applications\\devenv.exe\\shell\\edit\\command" | egrep -i '[A-Z]:\\' | cut -d\" -f2 | sed 's%\\%/%g' | tr -d '\r\n')
SIGNTOOL := $(shell reg query "HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Microsoft SDKs\\Windows\\v8.1" /v "InstallationFolder" | egrep InstallationFolder | cut -d ' ' -f13- | sed 's%\\%/%g' | tr -d '\r\n' | sed 's%$$%bin/x86/signtool.exe%')
export NMAP_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NMAP_VERSION' ../nmap.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
export NMAP_NUM_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NMAP_NUM_VERSION' ../nmap.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
export NPCAP_VERSION := $(shell ls npcap-*.exe | sed -e 's/npcap-\([-r0-9.]*\)\.exe/\1/' -e 'q')
COMMA_VERSION=$(shell echo $(NMAP_NUM_VERSION) | tr '.' ',')
LOGLOC=c:nmapbuild.log
NSE_FILES = ../scripts/script.db ../scripts/*.nse
NMAP_MSWIN32_AUX = ../../nmap-mswin32-aux
SIGNTOOL_ARGS = sign /a /n "Insecure.Com LLC" /tr http://timestamp.digicert.com /td sha256 /fd sha256
# escape quotes for NSIS
# escape for right side of sed regex replace
SIGNTOOL_SUBST = $(shell echo '"$(SIGNTOOL)" $(SIGNTOOL_ARGS)' | sed -e 's/"/$$\\"/g' -e 's/[\/&]/\\&/g' )

PRODUCT_NAME=Nmap
PLATFORM=Win32
BASE_CONFIG ?= Release
VCCONFIG=$(BASE_CONFIG)
NSIS_DEFINES=
ifdef NMAP_OEM
PRODUCT_NAME=Nmap OEM
OEM_SUFFIX=-oem
VCCONFIG=$(BASE_CONFIG)OEM
NSIS_DEFINES="/DNMAP_OEM=1"
endif

bundle-nmap: bundle-zip bundle-nsis

build-nmap: nmap.sln nmap.rc
	"$(VCEXPRESS)" nmap.sln /build "$(VCCONFIG)|$(PLATFORM)" /out $(LOGLOC)

stage-nmap: build-nmap LICENSE
	rm -rf nmap-$(NMAP_VERSION)
	mkdir nmap-$(NMAP_VERSION)
	cp ../CHANGELOG ../COPYING ../nmap-mac-prefixes ../nmap-os-db ../nmap-payloads ../nmap-protocols ../nmap-rpc ../nmap-service-probes ../nmap-services $(VCCONFIG)/nmap.exe ../docs/nmap.xsl ../nse_main.lua nmap_performance.reg ../README-WIN32 ../docs/3rd-party-licenses.txt nmap-$(NMAP_VERSION)/
# Use "cmd /c copy" rather than "cp" to preserve Windows ACLs. Using
# "cp" means that the copied DLLs don't have the same ACL and cause an
# error on startup: 0xc0000022.
	cmd /c copy $(subst /,\\,$(NMAP_MSWIN32_AUX))\\OpenSSL\\bin\\*.dll nmap-$(NMAP_VERSION)
	cmd /c copy ..\\libssh2\\win32\\$(BASE_CONFIG)_dll\\libssh2.dll nmap-$(NMAP_VERSION)
	cmd /c copy ..\\libz\\contrib\\vstudio\\vc12\\x86\\ZlibDll$(BASE_CONFIG)WithoutAsm\\zlibwapi.dll nmap-$(NMAP_VERSION)
	mkdir nmap-$(NMAP_VERSION)/scripts
	cp -f $(NSE_FILES) nmap-$(NMAP_VERSION)/scripts/
	for f in `cd .. && find nselib -name .svn -prune -o -type d -print`; do \
		mkdir -p nmap-$(NMAP_VERSION)/$$f; \
	done
	for f in `cd .. && find nselib -name .svn -prune -o -type f -print`; do \
		cp -f ../$$f nmap-$(NMAP_VERSION)/$$f; \
	done
	cp -r ../docs/licenses nmap-$(NMAP_VERSION)/
	rm -rf nmap-$(NMAP_VERSION)/licenses/.svn
	# TODO: change "-oem" to "$(OEM_SUFFIX)" when Npcap OEM is no longer needed for standard Nmap.
	cp npcap-$(NPCAP_VERSION)-oem.exe nmap-$(NMAP_VERSION)
	cp $(NMAP_MSWIN32_AUX)/vcredist_x86.exe nmap-$(NMAP_VERSION)
	cp $(NMAP_MSWIN32_AUX)/vcredist2008_x86.exe nmap-$(NMAP_VERSION)
	cp ../ncat/$(BASE_CONFIG)/ncat.exe nmap-$(NMAP_VERSION)
	cp ../ncat/$(BASE_CONFIG)/ca-bundle.crt nmap-$(NMAP_VERSION)
	cp ../nping/$(BASE_CONFIG)/nping.exe nmap-$(NMAP_VERSION)
# Install the ndiff batch file wrapper in the zip distribution.
	cp ../ndiff/ndiff.py nmap-$(NMAP_VERSION)/ndiff.py
	cp python-wrap.bat nmap-$(NMAP_VERSION)/ndiff.bat
	cd ../zenmap && install_scripts/windows/copy_and_compile.bat
	cp -R ../zenmap/dist/* nmap-$(NMAP_VERSION)/
	cp ../zenmap/README nmap-$(NMAP_VERSION)/ZENMAP_README
	cp ../zenmap/COPYING_HIGWIDGETS nmap-$(NMAP_VERSION)
	cp ../ndiff/README nmap-$(NMAP_VERSION)/NDIFF_README

sign-files: nmap-$(NMAP_VERSION)/nmap.exe nmap-$(NMAP_VERSION)/ncat.exe nmap-$(NMAP_VERSION)/nping.exe nmap-$(NMAP_VERSION)/ndiff.exe nmap-$(NMAP_VERSION)/zenmap.exe nmap-$(NMAP_VERSION)/libssh2.dll nmap-$(NMAP_VERSION)/libeay32.dll nmap-$(NMAP_VERSION)/ssleay32.dll nmap-$(NMAP_VERSION)/zlibwapi.dll
	# TODO: evaluate whether we should also sign the Python stuff for Zenmap, Ndiff
	"$(SIGNTOOL)" $(SIGNTOOL_ARGS) $^

bundle-nsis: nsis/Nmap.nsi sign-files
	cp nsis/AddToPath.nsh nsis/Nmap.nsi nsis/shortcuts.ini nsis/final.ini nmap-$(NMAP_VERSION)
	$(MAKENSIS) "/XOutFile nmap-$(NMAP_VERSION)$(OEM_SUFFIX)-setup.exe" $(NSIS_DEFINES) nmap-$(NMAP_VERSION)/Nmap.nsi
	mv nmap-$(NMAP_VERSION)/nmap-$(NMAP_VERSION)$(OEM_SUFFIX)-setup.exe .
	"$(SIGNTOOL)" $(SIGNTOOL_ARGS) nmap-$(NMAP_VERSION)$(OEM_SUFFIX)-setup.exe

bundle-zip: sign-files
	rm -f nmap-$(NMAP_VERSION)$(OEM_SUFFIX)-win32.zip
	zip -x nmap-$(NMAP_VERSION)/ZENMAP_README nmap-$(NMAP_VERSION)/zenmap/\* \
	  nmap-$(NMAP_VERSION)/zenmap.exe nmap-$(NMAP_VERSION)/share/\* \
	  nmap-$(NMAP_VERSION)/python27.dll nmap-$(NMAP_VERSION)/py2exe/\* \
	  nmap-$(NMAP_VERSION)/COPYING_HIGWIDGETS nmap-$(NMAP_VERSION)/w9xpopen.exe \
	  nmap-$(NMAP_VERSION)/vcredist2008_x86.exe \
	  nmap-$(NMAP_VERSION)/ndiff.exe nmap-$(NMAP_VERSION)/\*.ini \
	  nmap-$(NMAP_VERSION)/Uninstall.exe nmap-$(NMAP_VERSION)/\*.nsi \
	  nmap-$(NMAP_VERSION)/\*.nsh \
	  -r nmap-$(NMAP_VERSION)$(OEM_SUFFIX)-win32.zip nmap-$(NMAP_VERSION)

nmap.rc: nmap.rc.in ../nmap.h
	sed -e '1i// Automatically generated from $<.' \
	     -e 's/@@FILEVERSION@@/"$(NMAP_VERSION)\\0"/' \
	     -e 's/@@COMMAVERSION@@/$(COMMA_VERSION)/' \
	     -e 's/@@PRODUCT_NAME@@/$(PRODUCT_NAME)/' \
	     "$<" > "$@"

nsis/Nmap.nsi: nsis/Nmap.nsi.in ../nmap.h
	test -n "$(NPCAP_VERSION)" # Make sure NPcap is present
	sed -e '1i; Automatically generated from $<.' \
	     -e 's/@@VIPRODUCTVERSION@@/"$(NMAP_NUM_VERSION)"/' \
	     -e 's/@@VERSION@@/"$(NMAP_VERSION)"/' \
	     -e 's/@@NPCAP_VERSION@@/$(NPCAP_VERSION)/' \
	     -e 's/@@SIGNTOOL@@/$(SIGNTOOL_SUBST)/' \
	     -e 's/@@OEM_SUFFIX@@/$(OEM_SUFFIX)/' \
	     -e 's/@@PRODUCT_NAME@@/$(PRODUCT_NAME)/' \
	     "$<" > "$@"

LICENSE: ../COPYING
	./license-format/licformat.sh "$<" > "$@"

clean:
	"$(VCEXPRESS)" nmap.sln /clean
	rm -rf Debug Release ReleaseOEM nmapbuild.log nmap.rc nsis/Nmap.nsi LICENSE
