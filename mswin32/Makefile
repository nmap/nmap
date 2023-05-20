export MSYS2_ARG_CONV_EXCL=*
MAKENSIS=C:/Program Files (x86)/NSIS/makensis.exe
SIGNTOOL := $(shell reg query "HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Microsoft SDKs\\Windows\\v10.0" /v "InstallationFolder" | egrep InstallationFolder | cut -d ' ' -f13- | sed 's%\\%/%g' | tr -d '\r\n' | sed 's%$$%bin/x86/signtool.exe%')
NMAPDIR=..
NMAPDIR_WIN=$(shell echo '$(NMAPDIR)' | sed 's|/cygdrive/\(.\)|\1:|;s|/|\\|g')
ZENMAP_WINDIR=$(NMAPDIR)/zenmap/install_scripts/windows

include make-vars.make
export NPCAP_VERSION := $(shell ls npcap-*.exe | sed -e 's/npcap-\([0-9.]*\)[-oem]*\.exe/\1/' -e 'q')

NSE_FILES = $(NMAPDIR)/scripts/script.db $(NMAPDIR)/scripts/*.nse
NMAP_MSWIN32_AUX = $(NMAPDIR)/../nmap-mswin32-aux
SIGNTOOL_ARGS = sign /a /n "Insecure.Com LLC" /tr http://timestamp.digicert.com /td sha256 /fd sha256

PLATFORM=Win32
VCCONFIG=Release

all: build-nmap

check:
	test -n "$(NMAP_NAME)"
	test -n "$(NMAP_OEM_NAME)"
	test -n "$(NMAP_VERSION)"
	test -n "$(NMAP_NUM_VERSION)"

make-vars.make: make-vars.h
	cmd /c Build.bat Vars

bundle-nmap: bundle-zip bundle-nsis

build-nmap${OEM_SUFFIX}: nmap.sln
	cmd /c Build.bat Build "$(VCCONFIG)${OEM_SUFFIX}"

stage-common: $(NMAPDIR)/CHANGELOG $(NMAPDIR)/LICENSE $(NMAPDIR)/nmap-mac-prefixes $(NMAPDIR)/nmap-os-db $(NMAPDIR)/nmap-protocols $(NMAPDIR)/nmap-rpc $(NMAPDIR)/nmap-service-probes $(NMAPDIR)/nmap-services $(NMAPDIR)/docs/nmap.xsl $(NMAPDIR)/nse_main.lua $(NMAPDIR)/mswin32/nmap_performance.reg $(NMAPDIR)/README-WIN32 $(NMAPDIR)/docs/3rd-party-licenses.txt icon1.ico LICENSE.formatted vc_redist.x86.exe
	mkdir -p nmap-$(NMAP_VERSION)
	cp $^ nmap-$(NMAP_VERSION)/
# Use "cmd /c copy" rather than "cp" to preserve Windows ACLs. Using
# "cp" means that the copied DLLs don't have the same ACL and cause an
# error on startup: 0xc0000022.
	cmd /c copy $(subst /,\\,$(NMAP_MSWIN32_AUX))\\OpenSSL\\bin\\*.dll nmap-$(NMAP_VERSION)
	cmd /c copy $(NMAPDIR_WIN)\\libssh2\\win32\\$(VCCONFIG)_dll\\libssh2.dll nmap-$(NMAP_VERSION)
	cmd /c copy $(NMAPDIR_WIN)\\libz\\contrib\\vstudio\\vc14\\x86\\ZlibDll$(VCCONFIG)WithoutAsm\\zlibwapi.dll nmap-$(NMAP_VERSION)
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
	cp vc_redist.x86.exe nmap-$(NMAP_VERSION)
	cp $(NMAPDIR)/ncat/$(VCCONFIG)/ncat.exe nmap-$(NMAP_VERSION)
	cp $(NMAPDIR)/ncat/$(VCCONFIG)/ca-bundle.crt nmap-$(NMAP_VERSION)
	cp $(NMAPDIR)/nping/$(VCCONFIG)/nping.exe nmap-$(NMAP_VERSION)
# Install the ndiff batch file wrapper in the zip distribution.
	cp $(NMAPDIR)/ndiff/ndiff.py nmap-$(NMAP_VERSION)/ndiff.py
	cp python-wrap.bat nmap-$(NMAP_VERSION)/ndiff.bat
	$(MAKE) -C $(ZENMAP_WINDIR)
	rm -rf nmap-$(NMAP_VERSION)/zenmap
	cp -R $(ZENMAP_WINDIR)/dist/zenmap-w64/mingw64 nmap-$(NMAP_VERSION)/zenmap
	cp $(NMAPDIR)/zenmap/README nmap-$(NMAP_VERSION)/ZENMAP_README
	cp $(NMAPDIR)/zenmap/COPYING_HIGWIDGETS nmap-$(NMAP_VERSION)
	cp $(NMAPDIR)/ndiff/README nmap-$(NMAP_VERSION)/NDIFF_README

stage: stage-nmap stage-nmap-oem stage-common

stage-nmap:
	$(MAKE)	OEM_SUFFIX= stage-nmap-main

stage-nmap-oem:
	$(MAKE)	OEM_SUFFIX=-oem stage-nmap-main

stage-nmap-main: build-nmap${OEM_SUFFIX}
	mkdir -p nmap-$(NMAP_VERSION)${OEM_SUFFIX}
	cp $(VCCONFIG)${OEM_SUFFIX}/nmap.exe nmap-$(NMAP_VERSION)${OEM_SUFFIX}/

sign-files: nmap-$(NMAP_VERSION)-oem/nmap.exe nmap-$(NMAP_VERSION)/nmap.exe nmap-$(NMAP_VERSION)/ncat.exe nmap-$(NMAP_VERSION)/nping.exe nmap-$(NMAP_VERSION)/libssh2.dll nmap-$(NMAP_VERSION)/libcrypto-3.dll nmap-$(NMAP_VERSION)/libssl-3.dll nmap-$(NMAP_VERSION)/zlibwapi.dll
	# TODO: evaluate whether we should also sign the Python stuff for Zenmap, Ndiff
	"$(SIGNTOOL)" $(SIGNTOOL_ARGS) $^
	touch sign-files

NSIS_COMMON_ARGS = "/DVERSION=$(NMAP_VERSION)" "/DNUM_VERSION=$(NMAP_NUM_VERSION)" "/DNPCAP_VERSION=$(NPCAP_VERSION)"
bundle-nsis: sign-files
	rm -f nmap-$(NMAP_VERSION)*/tempinstaller.exe nmap-$(NMAP_VERSION)*/Uninstall.exe
	# Make the uninstallers
	"$(MAKENSIS)" /DINNER $(NSIS_COMMON_ARGS) "/DNMAP_NAME=$(NMAP_NAME)" nsis/Nmap.nsi
	nmap-$(NMAP_VERSION)/tempinstaller.exe || test $$? -eq 2
	test -f nmap-$(NMAP_VERSION)/Uninstall.exe
	"$(MAKENSIS)" /DINNER $(NSIS_COMMON_ARGS) "/DNMAP_NAME=$(NMAP_OEM_NAME)" "/DNMAP_OEM=1" nsis/Nmap.nsi
	nmap-$(NMAP_VERSION)-oem/tempinstaller.exe || test $$? -eq 2
	test -f nmap-$(NMAP_VERSION)-oem/Uninstall.exe
	# Sign uninstallers
	"$(SIGNTOOL)" $(SIGNTOOL_ARGS) nmap-$(NMAP_VERSION)/Uninstall.exe nmap-$(NMAP_VERSION)-oem/Uninstall.exe
	# Now build the installers
	"$(MAKENSIS)" $(NSIS_COMMON_ARGS) "/DNMAP_NAME=$(NMAP_NAME)" nsis/Nmap.nsi
	"$(MAKENSIS)" $(NSIS_COMMON_ARGS) "/DNMAP_NAME=$(NMAP_OEM_NAME)" "/DNMAP_OEM=1" nsis/Nmap.nsi
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
	  nmap-$(NMAP_VERSION)${OEM_SUFFIX}/COPYING_HIGWIDGETS \
	  nmap-$(NMAP_VERSION)${OEM_SUFFIX}/Uninstall.exe \
	  nmap-$(NMAP_VERSION)${OEM_SUFFIX}/icon1.ico \
	  -r nmap-$(NMAP_VERSION)${OEM_SUFFIX}-win32.zip nmap-$(NMAP_VERSION)${OEM_SUFFIX}
	rm nmap-$(NMAP_VERSION)${OEM_SUFFIX}/npcap-$(NPCAP_VERSION)${OEM_SUFFIX}.exe

LICENSE.formatted: $(NMAPDIR)/LICENSE
	./license-format/licformat.sh "$<" > "$@"

clean:
	cmd /c Build.bat Clean "$(VCCONFIG)${OEM_SUFFIX}"
	$(MAKE) -C $(ZENMAP_WINDIR) clean
	rm -rf make-vars.make nmap-$(NMAP_VERSION) nmap-$(NMAP_VERSION)-oem Debug Release Release-oem msbuild.log LICENSE.formatted
