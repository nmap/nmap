# This makefile builds a disk image (.dmg) containing the Zenmap application
# bundle.

NMAP_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NMAP_VERSION' ../nmap.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
NMAP_NUM_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NMAP_NUM_VERSION' ../nmap.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')

IMAGE_NAME = zenmap-$(NMAP_VERSION)$(if $(APPENDAGE),-$(APPENDAGE))
STAGING_DIR = $(IMAGE_NAME)

DIST_FILES = $(addprefix $(STAGING_DIR)/,Zenmap.app COPYING README)

$(IMAGE_NAME).dmg: $(DIST_FILES)
	rm -f $@
	hdiutil create -imagekey zlib-level=9 -srcfolder $(STAGING_DIR) $@

$(STAGING_DIR)/Zenmap.app:
	mkdir -p $(STAGING_DIR)
	cd ../zenmap && install_scripts/macosx/make-bundle.sh
	cp -rf ../zenmap/dist/Zenmap.app $(STAGING_DIR)/

$(STAGING_DIR)/README:
	mkdir -p $(STAGING_DIR)
	cp -f README $(STAGING_DIR)/

$(STAGING_DIR)/COPYING:
	mkdir -p $(STAGING_DIR)
	cp -f ../COPYING $(STAGING_DIR)/

clean:
	rm -rf $(STAGING_DIR)
	rm -f $(IMAGE_NAME).dmg

.PHONY: clean
