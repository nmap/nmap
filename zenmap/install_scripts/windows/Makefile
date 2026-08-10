export MSYS2_ARG_CONV_EXCL=""
MINGW_PREFIX=mingw-w64-x86_64
all: dist/zenmap-w64-deletelog.txt $(MINGW_PREFIX)-python-zenmap-*.pkg.tar.zst
	./build.sh

$(MINGW_PREFIX)-python-zenmap-%.pkg.tar.zst: PKGBUILD
	#pacman -Sy
	pacman -R --noconfirm $(MINGW_PREFIX)-python-zenmap || true
	makepkg-mingw -sfLi --noconfirm

dist/zenmap-w64-deletelog.txt: tmp.cfg mingw-w64-x86_64-python-zenmap-*.pkg.tar.zst
	styrene -p . -o $(dir $@) tmp.cfg --no-exe --no-zip

tmp.cfg: styrene.cfg ../utils/get_deps.py $(MINGW_PREFIX)-python-zenmap-*.pkg.tar.zst
	python3 ../utils/get_deps.py $@ $<

clean:
	rm -rf tmp.cfg pkg/ src/ dist/ mingw-w64-*-package.log* mingw-w64-*.zst
