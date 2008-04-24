# This makefile builds a disk image (.dmg) containing the Zenmap application
# bundle.

NMAP_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NMAP_VERSION' ../nmap.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
NMAP_NUM_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NMAP_NUM_VERSION' ../nmap.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')

NAME_VERSION = nmap-$(NMAP_VERSION)$(if $(APPENDAGE),-$(APPENDAGE))

IMAGE_STAGING_DIR = $(NAME_VERSION)
NMAP_STAGING_DIR = Nmap
ZENMAP_STAGING_DIR = Zenmap
NMAP_BUILD_DIR = nmap-build

IMAGE_NAME = $(NAME_VERSION).dmg
PKG_NAME = $(NAME_VERSION).mpkg

PREFIX = /usr/local

PACKAGEMAKER = /Developer/usr/bin/packagemaker

EXTRA_DIST_FILES = $(addprefix $(IMAGE_STAGING_DIR)/,COPYING README)

$(IMAGE_NAME): $(IMAGE_STAGING_DIR)/$(PKG_NAME) $(EXTRA_DIST_FILES)
	rm -f $@
	hdiutil create -imagekey zlib-level=9 -srcfolder $(IMAGE_STAGING_DIR) $@

$(IMAGE_STAGING_DIR)/$(PKG_NAME): stage-nmap stage-zenmap
	mkdir -p $(IMAGE_STAGING_DIR)
	$(PACKAGEMAKER) --doc nmap.pmdoc --title "Nmap $(NMAP_VERSION)" -o $@

stage-nmap:
	rm -rf $(NMAP_BUILD_DIR)
	svn export .. $(NMAP_BUILD_DIR)
	svn export ../nsock $(NMAP_BUILD_DIR)/nsock
	svn export ../nbase $(NMAP_BUILD_DIR)/nbase
	svn export ../zenmap $(NMAP_BUILD_DIR)/zenmap
	cd $(NMAP_BUILD_DIR) && ./configure --prefix="$(PREFIX)" --without-zenmap --with-libdnet=included --with-libpcap=included --with-libpcre=included --with-liblua=included
	make -C $(NMAP_BUILD_DIR)
	rm -rf $(NMAP_STAGING_DIR)
	make -C $(NMAP_BUILD_DIR) install DESTDIR="`pwd`/$(NMAP_STAGING_DIR)"

stage-zenmap:
	mkdir -p $(ZENMAP_STAGING_DIR)/Applications
	cd ../zenmap && install_scripts/macosx/make-bundle.sh
	cp -rf ../zenmap/dist/Zenmap.app $(ZENMAP_STAGING_DIR)/Applications/

$(IMAGE_STAGING_DIR)/README:
	mkdir -p $(IMAGE_STAGING_DIR)
	cp -f README $(IMAGE_STAGING_DIR)/

$(IMAGE_STAGING_DIR)/COPYING:
	mkdir -p $(IMAGE_STAGING_DIR)
	cp -f ../COPYING $(IMAGE_STAGING_DIR)/

clean:
	rm -rf $(IMAGE_STAGING_DIR)
	rm -rf $(NMAP_STAGING_DIR)
	rm -rf $(ZENMAP_STAGING_DIR)
	rm -rf $(NMAP_BUILD_DIR)
	rm -f $(IMAGE_NAME)

.PHONY: clean
