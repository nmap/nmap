# This makefile builds a disk image (.dmg) containing the installer for Nmap,
# Zenmap, Ncat, and Ndiff.

export NMAP_VERSION := $(shell echo NMAP_VERSION | $(CPP) -imacros ../nmap.h - | sed -n '$$s/[" ]//g;$$p')
OSX_VERSION=$(shell sw_vers -productVersion | cut -d'.' -f1,2 | tr -d ' ')
export OSX_MIN_VERSION = 10.15

NAME_VERSION = nmap-$(NMAP_VERSION)$(if $(APPENDAGE),-$(APPENDAGE))

IMAGE_NAME = $(NAME_VERSION).dmg
PKG_NAME = $(NAME_VERSION).mpkg

IMAGE_STAGING_DIR = $(NAME_VERSION)

JHBUILD_PREFIX=$(HOME)/gtk/inst
JHBUILD_SOURCE=$(HOME)/gtk/source

# Extra distribution file names
README_FILE = README.md
LICENSE_FILE = LICENSE
3RD_P_LIC_FILE = 3rd-party-licenses.txt
LICENSES_FILE = licenses

EXTRA_DIST = README.md ../LICENSE ../docs/3rd-party-licenses.txt ../docs/licenses

CFLAGS = -mmacosx-version-min=$(OSX_MIN_VERSION)
CXXFLAGS = -mmacosx-version-min=$(OSX_MIN_VERSION)

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

tool-checks: have-jhbuild have-gtk-mac-bundler

have-%:
	which $*

# Create packages (.pkg) for all the components to install in the installer (.mpkg)
PKGBUILD=pkgbuild --version $(NMAP_VERSION) --scripts Scripts --install-location /Applications --min-os-version $(OSX_MIN_VERSION)
%.pkg: check-%
	$(PKGBUILD) --root $*-root --identifier org.insecure.nmap.$* $@
nmap.pkg: check-nmap
	$(PKGBUILD) --root nmap-root --identifier org.insecure.nmap $@
zenmap.pkg: check-zenmap
	$(PKGBUILD) --root zenmap-root --identifier org.insecure.nmap.zenmap $@

#$(IMAGE_STAGING_DIR)/$(PKG_NAME): nmap.pkg ncat.pkg ndiff.pkg zenmap.pkg nping.pkg LICENSE.formatted
$(IMAGE_STAGING_DIR)/$(PKG_NAME): nmap.pkg ncat.pkg zenmap.pkg nping.pkg LICENSE.formatted
	rm -rf $(IMAGE_STAGING_DIR)
	mkdir -p $(IMAGE_STAGING_DIR)
	cp -rf $(EXTRA_DIST) $(IMAGE_STAGING_DIR)/

	# Produce a .xml with packages information
	productbuild --synthesize \
		--package 'nmap.pkg' \
		--package 'ncat.pkg' \
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
	(find $*-root -perm -a+x -type f -exec otool -l {} \; | awk '/:$$/{e=$$0}$$1=="minos"&&$$2!="$(OSX_MIN_VERSION)"{x=1;print e; print}END{exit x}' ) && echo "Bins are clean"

check-zenmap: stage-zenmap
	(find zenmap-build -perm -a+x -type f | xargs otool -L | awk '/:$$/{e=$$0}index($$0,"$(JHBUILD_PREFIX)"){x=1;print e; print}END{exit x}') && echo "Libs are clean"
	(find zenmap-build -perm -a+x -type f -exec otool -l {} \; | awk '/:$$/{e=$$0}$$1=="minos"&&$$2!="$(OSX_MIN_VERSION)"{x=1;print e; print}END{exit x}' ) && echo "Bins are clean"

export-%:
	rm -rf $*
# Using @BASE discards local changes.
	svn export .. $*

NMAP_TARBALL=$(JHBUILD_SOURCE)/pkgs/nmap-$(NMAP_VERSION).tar.gz
$(NMAP_TARBALL):
	rm -rf nmap-$(NMAP_VERSION)
	svn export .. nmap-$(NMAP_VERSION)
	tar czf nmap-$(NMAP_VERSION).tar.gz nmap-$(NMAP_VERSION)
	cp nmap-$(NMAP_VERSION).tar.gz $(JHBUILD_SOURCE)/pkgs/

openssl.modules: ../nmap.h
	sed -i.bak '/ENTITY nmap_version/s/\".*\"/\"$(NMAP_VERSION)\"/' $@

clean-%: openssl.modules
	jhbuild -m "file://`pwd`/openssl.modules" uninstall $*

build-%: $(NMAP_TARBALL) openssl.modules
	jhbuild -m "file://`pwd`/openssl.modules" build $*

stage-%: build-%
	sh make-app.sh $* "$(JHBUILD_PREFIX)"

stage-zenmap: export-zenmap-build
	jhbuild run zenmap-build/zenmap/install_scripts/macosx/make-bundle.sh

build-ndiff:
	echo Nothing to do

LICENSE.formatted:
# Use the license formatter from the Windows installer.
	../mswin32/license-format/licformat.sh ../LICENSE > $@

clean: clean-nmap clean-ncat clean-nping
	rm -rf $(IMAGE_STAGING_DIR)
	rm -rf *-build/
	rm -rf *-root/
	rm -f LICENSE.formatted
	rm -f $(IMAGE_NAME)
	rm -rf distribution.xml finalDist.xml nmap.pkg ncat.pkg ndiff.pkg nping.pkg zenmap.pkg

.PHONY: clean export-% stage-%
