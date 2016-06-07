# This makefile builds a disk image (.dmg) containing the installer for Nmap,
# Zenmap, Ncat, and Ndiff.

NMAP_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NMAP_VERSION' ../nmap.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
NMAP_NUM_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NMAP_NUM_VERSION' ../nmap.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
OSX_VERSION=$(shell sw_vers -productVersion | cut -d'.' -f1,2 | tr -d ' ')
OSX_MIN_VERSION = 10.8

NAME_VERSION = nmap-$(NMAP_VERSION)$(if $(APPENDAGE),-$(APPENDAGE))

IMAGE_NAME = $(NAME_VERSION).dmg
PKG_NAME = $(NAME_VERSION).mpkg

IMAGE_STAGING_DIR = $(NAME_VERSION)

NMAP_BUILD_DIR = nmap-build
NMAP_STAGING_DIR = Nmap

ZENMAP_BUILD_DIR = zenmap-build
ZENMAP_STAGING_DIR = Zenmap

NCAT_BUILD_DIR = ncat-build
NCAT_STAGING_DIR = Ncat

NDIFF_BUILD_DIR = ndiff-build
NDIFF_STAGING_DIR = Ndiff

NPING_BUILD_DIR = nping-build
NPING_STAGING_DIR = Nping

NMAP_UPDATE_BUILD_DIR = nmap-update-build
NMAP_UPDATE_STAGING_DIR = nmap-update

JHBUILD_PREFIX=$(HOME)/gtk/inst
export JHBUILD_PREFIX
# MACPORTS_PREFIX is still here because of nmap-update, which needs
# libsvn and libapr, which jhbuild doesn't support yet.
MACPORTS_PREFIX=$(HOME)/macports-10.8
PREFIX = /usr/local

PACKAGEMAKER = /Developer/usr/bin/packagemaker

EXTRA_DIST = README ../COPYING ../docs/3rd-party-licenses.txt ../docs/licenses

CONFIGURE_ARGS = --prefix="$(PREFIX)" --with-libdnet=included --with-libpcap=included --with-libpcre=included --with-liblua=included CC="$(CC)" CXX="$(CXX)" CFLAGS="$(CFLAGS)" CXXFLAGS="$(CXXFLAGS)" LDFLAGS="$(LDFLAGS)" PYTHON="$(PYTHON)"

# Flags for building universal binaries. See
# http://developer.apple.com/documentation/Porting/Conceptual/PortingUnix/compiling/chapter_4_section_3.html.
UNIVERSAL_CONFIGURE_ARGS = --disable-dependency-tracking
UNIVERSAL_CC = gcc
UNIVERSAL_CXX = g++
# Setting ARCHFLAGS separately is required. distutils.util.get_platform
# sniffs it to determine whether to return a universal architecture
# ("fat" or "universal") or a single one ("i386" or "ppc"). py2app in
# turn uses the arch value to decide which of its bootstrappers to
# install.
UNIVERSAL_ARCHFLAGS = -arch i386
UNIVERSAL_CPPFLAGS = -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX$(OSX_VERSION).sdk
UNIVERSAL_CFLAGS = $(UNIVERSAL_CPPFLAGS) -mmacosx-version-min=$(OSX_MIN_VERSION) $(UNIVERSAL_ARCHFLAGS)
UNIVERSAL_CXXFLAGS = $(UNIVERSAL_CFLAGS)
# https://stackoverflow.com/questions/19637164/c-linking-error-after-upgrading-to-mac-os-x-10-9-xcode-5-0-1/19637199#19637199
UNIVERSAL_LDFLAGS = -stdlib=libstdc++ -Wl,-syslibroot,/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX$(OSX_VERSION).sdk -mmacosx-version-min=$(OSX_MIN_VERSION) $(UNIVERSAL_ARCHFLAGS)

CC = $(UNIVERSAL_CC)
CXX = $(UNIVERSAL_CXX)
ARCHFLAGS += $(UNIVERSAL_ARCHFLAGS)
CONFIGURE_ARGS += $(UNIVERSAL_CONFIGURE_ARGS)
CPPFLAGS += $(UNIVERSAL_CPPFLAGS)
CFLAGS += $(UNIVERSAL_CFLAGS)
CXXFLAGS += $(UNIVERSAL_CXXFLAGS)
LDFLAGS += $(UNIVERSAL_LDFLAGS)

PYTHON = $(JHBUILD_PREFIX)/bin/python2.7
OPENSSL_STATIC = $(JHBUILD_PREFIX)/lib/libssl.a $(JHBUILD_PREFIX)/lib/libcrypto.a

$(IMAGE_NAME): path-check tool-checks $(IMAGE_STAGING_DIR)/$(PKG_NAME)
	rm -f $@
	hdiutil create -imagekey zlib-level=9 -srcfolder $(IMAGE_STAGING_DIR) $@

path-check:
	if (echo $(PATH) | grep -F "$(MACPORTS_PREFIX)"); then false; else echo "Path is OK"; fi

tool-checks: have-$(CC) have-jhbuild have-gtk-mac-bundler

have-%:
	which $*

$(IMAGE_STAGING_DIR)/$(PKG_NAME): check-nmap check-ncat check-ndiff check-zenmap check-nping check-nmap-update COPYING.formatted
	mkdir -p $(IMAGE_STAGING_DIR)
	cp -rf $(EXTRA_DIST) $(IMAGE_STAGING_DIR)/
	# create packages
	pkgbuild --root $(NCAT_STAGING_DIR) --identifier org.insecure.nmap.ncat --version $(NMAP_VERSION) --install-location / ncat.pkg
	pkgbuild --root $(NDIFF_STAGING_DIR) --identifier org.insecure.nmap.ndiff --version $(NMAP_VERSION) --install-location / ndiff.pkg
	pkgbuild --root $(NMAP_STAGING_DIR) --identifier org.insecure.nmap --version $(NMAP_VERSION) --install-location / nmap.pkg
	pkgbuild --root $(NPING_STAGING_DIR) --identifier org.insecure.nmap.nping --version $(NMAP_VERSION) --install-location / nping.pkg
	pkgbuild --root $(NMAP_UPDATE_STAGING_DIR) --identifier org.insecure.nmap.nmap-update --version $(NMAP_VERSION) --install-location / nmap-update.pkg
	pkgbuild --root $(ZENMAP_STAGING_DIR) --identifier org.insecure.nmap.zenmap --version $(NMAP_VERSION) --install-location /Applications zenmap.pkg

	# produce a .xml with packages informations
	productbuild --synthesize \
		--package 'ncat.pkg' \
		--package 'ndiff.pkg' \
		--package 'nmap.pkg' \
		--package 'nping.pkg' \
		--package 'nmap-update.pkg' \
		--package 'zenmap.pkg' \
		distribution.xml

	# make a new file and add background and titles attributes
	head -n 2 distribution.xml > finalDist.xml
	echo "    <title>Nmap $(NMAP_VERSION)</title>" >> finalDist.xml
	tail -n +3 distribution.xml >> finalDist.xml

	# build the .mpkg according to the final .xml file
	productbuild --distribution finalDist.xml --resources . --package-path . $(NAME_VERSION).mpkg

	mv $(NAME_VERSION).mpkg $(NAME_VERSION)/$(NAME_VERSION).mpkg
	rm -rf distribution.xml finalDist.xml ncat.pkg ndiff.pkg nmap.pkg nping.pkg nmap-update.pkg zenmap.pkg

check-%: stage-%
	if (find $* -perm -a+x -type f | xargs otool -L | grep -F "$(JHBUILD_PREFIX)"); then false; else echo "Libs are clean"; fi

export-%:
	rm -rf $*
# Using @BASE discards local changes.
	svn export .. $*

stage-nmap: export-$(NMAP_BUILD_DIR)
	cd $(NMAP_BUILD_DIR) && ./configure --without-zenmap --without-ncat --without-ndiff --without-nping --without-nmap-update --with-openssl="$(JHBUILD_PREFIX)" $(CONFIGURE_ARGS)
	make -C $(NMAP_BUILD_DIR) OPENSSL_LIBS="$(OPENSSL_STATIC)"
	rm -rf $(NMAP_STAGING_DIR)
	make -C $(NMAP_BUILD_DIR) install DESTDIR="`pwd`/$(NMAP_STAGING_DIR)" OPENSSL_LIBS="$(OPENSSL_STATIC)"

stage-ncat: export-$(NCAT_BUILD_DIR)
	cd $(NCAT_BUILD_DIR) && ./configure --without-zenmap --with-ncat --without-ndiff --without-nping --without-nmap-update --with-openssl="$(JHBUILD_PREFIX)" $(CONFIGURE_ARGS)
	make -C $(NCAT_BUILD_DIR) build-ncat OPENSSL_LIBS="$(OPENSSL_STATIC)"
	rm -rf $(NCAT_STAGING_DIR)
	make -C $(NCAT_BUILD_DIR) install-ncat DESTDIR="`pwd`/$(NCAT_STAGING_DIR)" OPENSSL_LIBS="$(OPENSSL_STATIC)"

stage-nping: export-$(NPING_BUILD_DIR)
	cd $(NPING_BUILD_DIR) && ./configure --without-zenmap --without-ncat --without-ndiff --with-nping --without-nmap-update --with-openssl="$(JHBUILD_PREFIX)" $(CONFIGURE_ARGS)
	make -C $(NPING_BUILD_DIR) build-nping OPENSSL_LIBS="$(OPENSSL_STATIC)"
	rm -rf $(NPING_STAGING_DIR)
	make -C $(NPING_BUILD_DIR) install-nping DESTDIR="`pwd`/$(NPING_STAGING_DIR)" OPENSSL_LIBS="$(OPENSSL_STATIC)"

stage-nmap-update: export-$(NMAP_UPDATE_BUILD_DIR)
	cd $(NMAP_UPDATE_BUILD_DIR) && ./configure --without-zenmap --without-ncat --without-ndiff --without-nping --with-nmap-update --with-apr=$(MACPORTS_PREFIX) --with-subversion=$(MACPORTS_PREFIX) $(CONFIGURE_ARGS)
	make -C $(NMAP_UPDATE_BUILD_DIR) build-nmap-update
	rm -rf $(NMAP_UPDATE_STAGING_DIR)
	make -C $(NMAP_UPDATE_BUILD_DIR) install-nmap-update DESTDIR="`pwd`/$(NMAP_UPDATE_STAGING_DIR)"
	install_name_tool -change "$(MACPORTS_PREFIX)/lib/libapr-1.0.dylib" "/usr/lib/libapr-1.0.dylib" "$(NMAP_UPDATE_STAGING_DIR)/usr/local/bin/nmap-update"
	install_name_tool -change "$(MACPORTS_PREFIX)/lib/libsvn_client-1.0.dylib" "/usr/lib/libsvn_client-1.0.dylib" "$(NMAP_UPDATE_STAGING_DIR)/usr/local/bin/nmap-update"
	install_name_tool -change "$(MACPORTS_PREFIX)/lib/libsvn_subr-1.0.dylib" "/usr/lib/libsvn_subr-1.0.dylib" "$(NMAP_UPDATE_STAGING_DIR)/usr/local/bin/nmap-update"

# make-bundle.sh uses these to build its authorization wrapper.
export CC ARCHFLAGS CPPFLAGS CFLAGS CXXFLAGS LDFLAGS

stage-zenmap: export-$(ZENMAP_BUILD_DIR)
	cd $(ZENMAP_BUILD_DIR)/zenmap && install_scripts/macosx/make-bundle.sh
	rm -rf $(ZENMAP_STAGING_DIR)
	mkdir -p $(ZENMAP_STAGING_DIR)/Applications
	cp -rf $(ZENMAP_BUILD_DIR)/zenmap/dist/Zenmap.app $(ZENMAP_STAGING_DIR)/Applications/

stage-ndiff: export-$(NDIFF_BUILD_DIR)
	mkdir -p $(NDIFF_STAGING_DIR)/usr/local/bin
	mkdir -p $(NDIFF_STAGING_DIR)/usr/local/share/man/man1
	cp $(NDIFF_BUILD_DIR)/ndiff/ndiff.py $(NDIFF_STAGING_DIR)/usr/local/bin/ndiff
	cp $(NDIFF_BUILD_DIR)/ndiff/docs/ndiff.1 $(NDIFF_STAGING_DIR)/usr/local/share/man/man1/

COPYING.formatted:
# Use the license formatter from the Windows installer.
	../mswin32/license-format/licformat.sh ../COPYING > $@

clean:
	rm -rf $(IMAGE_STAGING_DIR)
	rm -rf $(NMAP_BUILD_DIR)
	rm -rf $(NMAP_STAGING_DIR)
	rm -rf $(ZENMAP_BUILD_DIR)
	rm -rf $(ZENMAP_STAGING_DIR)
	rm -rf $(NCAT_BUILD_DIR)
	rm -rf $(NCAT_STAGING_DIR)
	rm -rf $(NDIFF_BUILD_DIR)
	rm -rf $(NDIFF_STAGING_DIR)
	rm -rf $(NPING_BUILD_DIR)
	rm -rf $(NPING_STAGING_DIR)
	rm -rf $(NMAP_UPDATE_BUILD_DIR)
	rm -rf $(NMAP_UPDATE_STAGING_DIR)
	rm -f COPYING.formatted
	rm -f $(IMAGE_NAME)

.PHONY: clean export-% stage-%
