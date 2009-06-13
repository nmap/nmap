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

PREFIX = /usr/local

PACKAGEMAKER = /Developer/usr/bin/packagemaker

EXTRA_DIST_FILES = $(addprefix $(IMAGE_STAGING_DIR)/,COPYING README)

CONFIGURE_ARGS = --prefix="$(PREFIX)" --with-libdnet=included --with-libpcap=included --with-libpcre=included --with-liblua=included CFLAGS="$(CFLAGS)" CXXFLAGS="$(CXXFLAGS)" LDFLAGS="$(LDFLAGS)"

# Flags for building universal binaries. See
# http://developer.apple.com/documentation/Porting/Conceptual/PortingUnix/compiling/chapter_4_section_3.html.
UNIVERSAL_CONFIGURE_ARGS = --disable-dependency-tracking
UNIVERSAL_CPPFLAGS = -isysroot /Developer/SDKs/MacOSX10.4u.sdk
UNIVERSAL_CFLAGS = $(UNIVERSAL_CPPFLAGS) -mmacosx-version-min=10.4 -arch ppc -arch i386
UNIVERSAL_CXXFLAGS = $(UNIVERSAL_CFLAGS)
UNIVERSAL_LDFLAGS = -Wl,-syslibroot,/Developer/SDKs/MacOSX10.4u.sdk -mmacosx-version-min=10.4 -arch ppc -arch i386

CONFIGURE_ARGS += $(UNIVERSAL_CONFIGURE_ARGS)
CPPFLAGS += $(UNIVERSAL_CPPFLAGS)
CFLAGS += $(UNIVERSAL_CFLAGS)
CXXFLAGS += $(UNIVERSAL_CXXFLAGS)
LDFLAGS += $(UNIVERSAL_LDFLAGS)

$(IMAGE_NAME): $(IMAGE_STAGING_DIR)/$(PKG_NAME) $(EXTRA_DIST_FILES)
	rm -f $@
	hdiutil create -imagekey zlib-level=9 -srcfolder $(IMAGE_STAGING_DIR) $@

$(IMAGE_STAGING_DIR)/$(PKG_NAME): stage-nmap stage-ncat stage-ndiff stage-zenmap README COPYING.formatted
	mkdir -p $(IMAGE_STAGING_DIR)
	$(PACKAGEMAKER) --doc nmap.pmdoc --title "Nmap $(NMAP_VERSION)" -o $@

export-%:
	rm -rf $*
# Using @BASE discards local changes.
	svn export ..@BASE $*
	svn export ../nbase@BASE $*/nbase
	svn export ../ncat@BASE $*/ncat
	svn export ../nsock@BASE $*/nsock
	svn export ../zenmap@BASE $*/zenmap

stage-nmap: export-$(NMAP_BUILD_DIR)
	cd $(NMAP_BUILD_DIR) && ./configure --without-zenmap --without-ncat --without-ndiff $(CONFIGURE_ARGS)
	make -C $(NMAP_BUILD_DIR)
	rm -rf $(NMAP_STAGING_DIR)
	make -C $(NMAP_BUILD_DIR) install DESTDIR="`pwd`/$(NMAP_STAGING_DIR)"

stage-ncat: export-$(NCAT_BUILD_DIR)
	cd $(NCAT_BUILD_DIR) && ./configure --without-zenmap --with-ncat --without-ndiff $(CONFIGURE_ARGS)
	make -C $(NCAT_BUILD_DIR)
	rm -rf $(NCAT_STAGING_DIR)
	make -C $(NCAT_BUILD_DIR) install-ncat DESTDIR="`pwd`/$(NCAT_STAGING_DIR)"

# make-bundle.sh uses these to build its authorization wrapper.
export CC CPPFLAGS CFLAGS CXXFLAGS LDFLAGS

stage-zenmap: export-$(ZENMAP_BUILD_DIR)
	cd $(ZENMAP_BUILD_DIR)/zenmap && install_scripts/macosx/make-bundle.sh
	rm -rf $(ZENMAP_STAGING_DIR)
	mkdir -p $(ZENMAP_STAGING_DIR)/Applications
	cp -rf $(ZENMAP_BUILD_DIR)/zenmap/dist/Zenmap.app $(ZENMAP_STAGING_DIR)/Applications/

stage-ndiff: export-$(NDIFF_BUILD_DIR)
	cd $(NDIFF_BUILD_DIR) && ./configure --without-zenmap --without-ncat --with-ndiff $(CONFIGURE_ARGS)
	make -C $(NDIFF_BUILD_DIR) build-ndiff
	rm -rf $(NDIFF_STAGING_DIR)
	make -C $(NDIFF_BUILD_DIR) install-ndiff DESTDIR="`pwd`/$(NDIFF_STAGING_DIR)"

$(IMAGE_STAGING_DIR)/README:
	mkdir -p $(IMAGE_STAGING_DIR)
	cp -f README $(IMAGE_STAGING_DIR)/

$(IMAGE_STAGING_DIR)/COPYING:
	mkdir -p $(IMAGE_STAGING_DIR)
	cp -f ../COPYING $(IMAGE_STAGING_DIR)/

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
	rm -f COPYING.formatted
	rm -f $(IMAGE_NAME)

.PHONY: clean export-% stage-%
