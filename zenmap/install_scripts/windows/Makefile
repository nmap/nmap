export MSYS2_ARG_CONV_EXCL=""
all: dist/zenmap-w64-deletelog.txt mingw-w64-x86_64-python-zenmap-*.pkg.tar.zst
	./build.sh

mingw-w64-x86_64-python-zenmap-%.pkg.tar.zst: PKGBUILD
	makepkg-mingw -RdfL

dist/zenmap-w64-deletelog.txt: tmp.cfg mingw-w64-x86_64-python-zenmap-*.pkg.tar.zst
	styrene -p . -o $(dir $@) tmp.cfg --no-exe --no-zip

tmp.cfg: styrene.cfg ../utils/get_deps.py
	python3 ../utils/get_deps.py $@ $<

clean:
	rm -rf tmp.cfg pkg/ src/ dist/ mingw-w64-*-package.log* mingw-w64-*.zst
