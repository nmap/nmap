# This makefile builds a disk image (.dmg) containing the installer for Nmap,
# Zenmap, Ncat, and Ndiff.

export NMAP_VERSION := $(shell echo NMAP_VERSION | $(CPP) -imacros ../nmap.h - | sed -n '$$s/[" ]//g;$$p')
OSX_VERSION=$(shell sw_vers -productVersion | cut -d'.' -f1,2 | tr -d ' ')
OSX_MIN_VERSION = 10.15

NAME_VERSION = nmap-$(NMAP_VERSION)$(if $(APPENDAGE),-$(APPENDAGE))

IMAGE_NAME = $(NAME_VERSION).dmg
PKG_NAME = $(NAME_VERSION).mpkg

IMAGE_STAGING_DIR = $(NAME_VERSION)

NMAP_BUILD_DIR = nmap-build
NMAP_STAGING_DIR = nmap-root

ZENMAP_BUILD_DIR = zenmap-build
ZENMAP_STAGING_DIR = zenmap-root

NCAT_BUILD_DIR = ncat-build
NCAT_STAGING_DIR = ncat-root

NDIFF_BUILD_DIR = ndiff-build
NDIFF_STAGING_DIR = ndiff-root

NPING_BUILD_DIR = nping-build
NPING_STAGING_DIR = nping-root

JHBUILD_PREFIX=$(HOME)/gtk/inst
JHBUILD_SOURCE=$(HOME)/gtk/source
PREFIX = /usr/local

# Extra distribution file names
README_FILE = README.md
LICENSE_FILE = LICENSE
3RD_P_LIC_FILE = 3rd-party-licenses.txt
LICENSES_FILE = licenses

EXTRA_DIST = README.md ../LICENSE ../docs/3rd-party-licenses.txt ../docs/licenses

CONFIGURE_ARGS = --prefix="$(PREFIX)" --with-libdnet=included --with-libpcap=included --with-libpcre=included --with-liblua=included CC="$(CC)" CXX="$(CXX)" CFLAGS="$(CFLAGS)" CXXFLAGS="$(CXXFLAGS)" LDFLAGS="$(LDFLAGS)" PYTHON="$(PYTHON)"

CFLAGS = -mmacosx-version-min=$(OSX_MIN_VERSION)
CXXFLAGS = -mmacosx-version-min=$(OSX_MIN_VERSION)

# Jhbuild static libraries
PYTHON = $(JHBUILD_PREFIX)/bin/python3
OPENSSL_STATIC = $(JHBUILD_PREFIX)/lib/libssl.a $(JHBUILD_PREFIX)/lib/libcrypto.a
LIBZ_STATIC = $(JHBUILD_PREFIX)/lib/libz.a

# These are the positions used by the createdmg.sh and check_test.sh scripts
export ICON_SIZE=88
export FONT_SIZE=13
export MPKG_POS_X=110
export MPKG_POS_Y=170
export APPS_POS_X=110
export APPS_POS_Y=310
export README_POS_X=802
export README_POS_Y=180
export LICENSE_POS_X=802
export LICENSE_POS_Y=310
export THIRD_P_POS_X=802
export THIRD_P_POS_Y=440
export LICENSES_POS_X=670
export LICENSES_POS_Y=60

$(IMAGE_NAME): tool-checks $(IMAGE_STAGING_DIR)/$(PKG_NAME)
	rm -f $@
	# Create the dmg disk image and convert it to read only disk
	./createdmg.sh $(IMAGE_STAGING_DIR) $(README_FILE) $(LICENSE_FILE) $(3RD_P_LIC_FILE) $(LICENSES_FILE)
	# Check the created disk image for the sizes, backgrounds and icons presence and positions
	./check_test.sh $(README_FILE) $(LICENSE_FILE) $(3RD_P_LIC_FILE) $(LICENSES_FILE)

tool-checks: have-$(CC) have-jhbuild have-gtk-mac-bundler

have-%:
	which $*

#$(IMAGE_STAGING_DIR)/$(PKG_NAME): check-nmap check-ncat check-ndiff check-zenmap check-nping LICENSE.formatted
$(IMAGE_STAGING_DIR)/$(PKG_NAME): check-nmap check-ncat check-ndiff check-zenmap check-nping LICENSE.formatted
	rm -rf $(IMAGE_STAGING_DIR)
	mkdir -p $(IMAGE_STAGING_DIR)
	cp -rf $(EXTRA_DIST) $(IMAGE_STAGING_DIR)/
	# Create packages (.pkg) for all the components to install in the installer (.mpkg)
	pkgbuild --root $(NMAP_STAGING_DIR) --identifier org.insecure.nmap --version $(NMAP_VERSION) --install-location /usr/local nmap.pkg
	pkgbuild --root $(NCAT_STAGING_DIR) --identifier org.insecure.nmap.ncat --version $(NMAP_VERSION) --install-location /usr/local ncat.pkg
	pkgbuild --root $(NDIFF_STAGING_DIR)/usr/local --identifier org.insecure.nmap.ndiff --version $(NMAP_VERSION) --install-location /usr/local ndiff.pkg
	pkgbuild --root $(NPING_STAGING_DIR) --identifier org.insecure.nmap.nping --version $(NMAP_VERSION) --install-location /usr/local nping.pkg
	pkgbuild --root $(ZENMAP_STAGING_DIR) --identifier org.insecure.nmap.zenmap --version $(NMAP_VERSION) --install-location /Applications zenmap.pkg

	# Produce a .xml with packages information
	productbuild --synthesize \
		--package 'nmap.pkg' \
		--package 'ncat.pkg' \
		--package 'ndiff.pkg' \
		--package 'nping.pkg' \
		--package 'zenmap.pkg' \
		distribution.xml

	# Make a new file and add background and title attributes
	head -n 2 distribution.xml > finalDist.xml
	echo "    <title>Nmap $(NMAP_VERSION)</title>" >> finalDist.xml
	# This line is for adding a background image to the .mpkg
	echo "    <background file=\"pkg_bg.jpg\" mime-type=\"image/jpeg\" scaling=\"proportional\" alignment=\"bottomleft\"/>" >> finalDist.xml
	tail -n +3 distribution.xml >> finalDist.xml

	# Build the .mpkg according to the final .xml file (and so all the .pkg)
	productbuild --distribution finalDist.xml --resources . --package-path . $(NAME_VERSION).mpkg

	mv $(NAME_VERSION).mpkg $(NAME_VERSION)/$(NAME_VERSION).mpkg

check-%: stage-%
	(find $*-root -perm -a+x -type f | xargs otool -L | awk '/:$$/{e=$$0}index($$0,"$(JHBUILD_PREFIX)"){x=1;print e; print}END{exit x}') && echo "Libs are clean"

export-%:
	rm -rf $*
# Using @BASE discards local changes.
	svn export .. $*

export-tarball:
	rm -rf nmap-$(NMAP_VERSION)
	svn export .. nmap-$(NMAP_VERSION)
	tar czf nmap-$(NMAP_VERSION).tar.gz nmap-$(NMAP_VERSION)
	cp nmap-$(NMAP_VERSION).tar.gz $(JHBUILD_SOURCE)/pkgs/

xstage-nmap: export-$(NMAP_BUILD_DIR)
	cd $(NMAP_BUILD_DIR) && ./configure --without-zenmap --without-ncat --without-ndiff --without-nping --with-openssl="$(JHBUILD_PREFIX)" --with-libz="$(JHBUILD_PREFIX)" $(CONFIGURE_ARGS)
	# LIB* is libssh2's name for *_LIBS
	make -C $(NMAP_BUILD_DIR) OPENSSL_LIBS="$(OPENSSL_STATIC)" LIBSSL="$(OPENSSL_STATIC)" ZLIB_LIBS="$(LIBZ_STATIC)" LIBZ="$(LIBZ_STATIC)"
	rm -rf $(NMAP_STAGING_DIR)
	make -C $(NMAP_BUILD_DIR) install DESTDIR="`pwd`/$(NMAP_STAGING_DIR)" OPENSSL_LIBS="$(OPENSSL_STATIC)" ZLIB_LIBS="$(LIBZ_STATIC)"

xstage-ncat: export-$(NCAT_BUILD_DIR)
	cd $(NCAT_BUILD_DIR) && ./configure --without-zenmap --with-ncat --without-ndiff --without-nping --with-openssl="$(JHBUILD_PREFIX)" $(CONFIGURE_ARGS)
	make -C $(NCAT_BUILD_DIR) build-ncat OPENSSL_LIBS="$(OPENSSL_STATIC)"
	rm -rf $(NCAT_STAGING_DIR)
	make -C $(NCAT_BUILD_DIR) install-ncat DESTDIR="`pwd`/$(NCAT_STAGING_DIR)" OPENSSL_LIBS="$(OPENSSL_STATIC)"

xstage-nping: export-$(NPING_BUILD_DIR)
	cd $(NPING_BUILD_DIR) && ./configure --without-zenmap --without-ncat --without-ndiff --with-nping --with-openssl="$(JHBUILD_PREFIX)" $(CONFIGURE_ARGS)
	make -C $(NPING_BUILD_DIR) build-nping OPENSSL_LIBS="$(OPENSSL_STATIC)"
	rm -rf $(NPING_STAGING_DIR)
	make -C $(NPING_BUILD_DIR) install-nping DESTDIR="`pwd`/$(NPING_STAGING_DIR)" OPENSSL_LIBS="$(OPENSSL_STATIC)"

openssl.modules: ../nmap.h
	sed -i.bak '/ENTITY nmap_version/s/\".*\"/\"$(NMAP_VERSION)\"/' $@

stage-%: export-tarball openssl.modules
	jhbuild -m "file://`pwd`/openssl.modules" build $*
	rm -rf $*-root
	mkdir $*-root
	rsync -a --files-from "$(JHBUILD_PREFIX)/_jhbuild/manifests/$*" "$(JHBUILD_PREFIX)" $*-root/

stage-zenmap: export-$(ZENMAP_BUILD_DIR)
	cd $(ZENMAP_BUILD_DIR)/zenmap && jhbuild run install_scripts/macosx/make-bundle.sh
	rm -rf $(ZENMAP_STAGING_DIR)
	mkdir -p $(ZENMAP_STAGING_DIR)
	cp -rf $(ZENMAP_BUILD_DIR)/zenmap/dist/Zenmap.app $(ZENMAP_STAGING_DIR)

stage-ndiff: export-$(NDIFF_BUILD_DIR)
	mkdir -p $(NDIFF_STAGING_DIR)/usr/local/bin
	mkdir -p $(NDIFF_STAGING_DIR)/usr/local/share/man/man1
	cp $(NDIFF_BUILD_DIR)/ndiff/ndiff.py $(NDIFF_STAGING_DIR)/usr/local/bin/ndiff
	cp $(NDIFF_BUILD_DIR)/ndiff/docs/ndiff.1 $(NDIFF_STAGING_DIR)/usr/local/share/man/man1/

LICENSE.formatted:
# Use the license formatter from the Windows installer.
	../mswin32/license-format/licformat.sh ../LICENSE > $@

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
	rm -f LICENSE.formatted
	rm -f $(IMAGE_NAME)
	rm -rf distribution.xml finalDist.xml nmap.pkg ncat.pkg ndiff.pkg nping.pkg zenmap.pkg

.PHONY: clean export-% stage-%
