# This makefile builds a disk image (.dmg) containing the Zenmap application
# bundle.

NMAP_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NMAP_VERSION' ../nmap.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
NMAP_NUM_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NMAP_NUM_VERSION' ../nmap.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')

STAGING_DIR = Zenmap-$(NMAP_VERSION)

DIST_FILES = $(addprefix $(STAGING_DIR)/,Zenmap.app)

Zenmap-$(NMAP_VERSION).dmg: $(STAGING_DIR) $(DIST_FILES)
	rm -f $@
	hdiutil create -imagekey zlib-level=9 -srcfolder $(STAGING_DIR) $@

$(STAGING_DIR)/Zenmap.app:
	mkdir $(STAGING_DIR)
	cd ../zenmap && install_scripts/macosx/make-bundle.sh
	mv -f ../zenmap/dist/Zenmap.app $(STAGING_DIR)

clean:
	rm -rf $(STAGING_DIR)
	rm -f Zenmap-$(NMAP_VERSION).dmg

.PHONY: clean
