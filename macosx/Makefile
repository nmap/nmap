# This makefile builds a disk image (.dmg) containing the installer for Nmap,
# Zenmap, Ncat, and Ndiff.

NMAP_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NMAP_VERSION' ../nmap.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
NMAP_NUM_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NMAP_NUM_VERSION' ../nmap.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')

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

MACPORTS_PREFIX=$(HOME)/macports-10.4u
PREFIX = /usr/local

PACKAGEMAKER = /Developer/usr/bin/packagemaker

EXTRA_DIST = README ../COPYING ../docs/3rd-party-licenses.txt ../docs/licenses

CONFIGURE_ARGS = --prefix="$(PREFIX)" --with-libdnet=included --with-libpcap=included --with-libpcre=included --with-liblua=included CC="$(CC)" CXX="$(CXX)" CFLAGS="$(CFLAGS)" CXXFLAGS="$(CXXFLAGS)" LDFLAGS="$(LDFLAGS)" PYTHON="$(PYTHON)"

# Flags for building universal binaries. See
# http://developer.apple.com/documentation/Porting/Conceptual/PortingUnix/compiling/chapter_4_section_3.html.
UNIVERSAL_CONFIGURE_ARGS = --disable-dependency-tracking
# gcc-4.0 is used to avoid an error with stdarg.h ("No such file or directory")
# when building against the 10.4u SDK on OS X 10.6.
UNIVERSAL_CC = gcc-4.0
UNIVERSAL_CXX = g++-4.0
# Setting ARCHFLAGS separately is required. distutils.util.get_platform
# sniffs it to determine whether to return a universal architecture
# ("fat" or "universal") or a single one ("i386" or "ppc"). py2app in
# turn uses the arch value to decide which of its bootstrappers to
# install.
UNIVERSAL_ARCHFLAGS = -arch ppc -arch i386
UNIVERSAL_CPPFLAGS = -isysroot /Developer/SDKs/MacOSX10.4u.sdk
UNIVERSAL_CFLAGS = $(UNIVERSAL_CPPFLAGS) -mmacosx-version-min=10.4 $(UNIVERSAL_ARCHFLAGS)
UNIVERSAL_CXXFLAGS = $(UNIVERSAL_CFLAGS)
UNIVERSAL_LDFLAGS = -Wl,-syslibroot,/Developer/SDKs/MacOSX10.4u.sdk -mmacosx-version-min=10.4 $(UNIVERSAL_ARCHFLAGS)

CC = $(UNIVERSAL_CC)
CXX = $(UNIVERSAL_CXX)
ARCHFLAGS += $(UNIVERSAL_ARCHFLAGS)
CONFIGURE_ARGS += $(UNIVERSAL_CONFIGURE_ARGS)
CPPFLAGS += $(UNIVERSAL_CPPFLAGS)
CFLAGS += $(UNIVERSAL_CFLAGS)
CXXFLAGS += $(UNIVERSAL_CXXFLAGS)
LDFLAGS += $(UNIVERSAL_LDFLAGS)

PYTHON = /usr/bin/python

$(IMAGE_NAME): $(IMAGE_STAGING_DIR)/$(PKG_NAME)
	rm -f $@
	hdiutil create -imagekey zlib-level=9 -srcfolder $(IMAGE_STAGING_DIR) $@

$(IMAGE_STAGING_DIR)/$(PKG_NAME): stage-nmap stage-ncat stage-ndiff stage-zenmap stage-nping COPYING.formatted
	mkdir -p $(IMAGE_STAGING_DIR)
	cp -rf $(EXTRA_DIST) $(IMAGE_STAGING_DIR)/
	$(PACKAGEMAKER) --doc nmap.pmdoc --title "Nmap $(NMAP_VERSION)" --no-relocate -o $@

export-%:
	rm -rf $*
# Using @BASE discards local changes.
	svn export ..@BASE $*

stage-nmap: export-$(NMAP_BUILD_DIR)
	cd $(NMAP_BUILD_DIR) && ./configure --without-zenmap --without-ncat --without-ndiff --without-nping $(CONFIGURE_ARGS)
	make -C $(NMAP_BUILD_DIR)
	rm -rf $(NMAP_STAGING_DIR)
	make -C $(NMAP_BUILD_DIR) install DESTDIR="`pwd`/$(NMAP_STAGING_DIR)"

stage-ncat: export-$(NCAT_BUILD_DIR)
	cd $(NCAT_BUILD_DIR) && ./configure --without-zenmap --with-ncat --without-ndiff --without-nping $(CONFIGURE_ARGS)
	make -C $(NCAT_BUILD_DIR)
	rm -rf $(NCAT_STAGING_DIR)
	make -C $(NCAT_BUILD_DIR) install-ncat DESTDIR="`pwd`/$(NCAT_STAGING_DIR)"

stage-nping: export-$(NPING_BUILD_DIR)
# Link against the local MacPorts openssl because the 10.4u SDK doesn't
# have EVP_sha256, used by Nping. We let configure find the libraries
# dynamically, then link with the static libraries with "make".
	cd $(NPING_BUILD_DIR) && ./configure --without-zenmap --without-ncat --without-ndiff --with-nping --with-openssl="$(MACPORTS_PREFIX)" $(CONFIGURE_ARGS)
	make -C $(NPING_BUILD_DIR) OPENSSL_LIBS="$(MACPORTS_PREFIX)/lib/libssl.a $(MACPORTS_PREFIX)/lib/libcrypto.a $(MACPORTS_PREFIX)/lib/libz.a"
	rm -rf $(NPING_STAGING_DIR)
	make -C $(NPING_BUILD_DIR) install-nping DESTDIR="`pwd`/$(NPING_STAGING_DIR)"

# make-bundle.sh uses these to build its authorization wrapper.
export CC ARCHFLAGS CPPFLAGS CFLAGS CXXFLAGS LDFLAGS

stage-zenmap: export-$(ZENMAP_BUILD_DIR)
	cd $(ZENMAP_BUILD_DIR)/zenmap && install_scripts/macosx/make-bundle.sh
	rm -rf $(ZENMAP_STAGING_DIR)
	mkdir -p $(ZENMAP_STAGING_DIR)/Applications
	cp -rf $(ZENMAP_BUILD_DIR)/zenmap/dist/Zenmap.app $(ZENMAP_STAGING_DIR)/Applications/

stage-ndiff: export-$(NDIFF_BUILD_DIR)
	cd $(NDIFF_BUILD_DIR) && ./configure --without-zenmap --without-ncat --with-ndiff --without-nping $(CONFIGURE_ARGS)
	make -C $(NDIFF_BUILD_DIR) build-ndiff
	rm -rf $(NDIFF_STAGING_DIR)
	make -C $(NDIFF_BUILD_DIR) install-ndiff DESTDIR="`pwd`/$(NDIFF_STAGING_DIR)"

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
	rm -f COPYING.formatted
	rm -f $(IMAGE_NAME)

.PHONY: clean export-% stage-%
