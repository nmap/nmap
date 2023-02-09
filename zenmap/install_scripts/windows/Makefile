all: dist/zenmap-w64-deletelog.txt mingw-w64-x86_64-python-zenmap-%.pkg.tar.zst
	./build.sh

mingw-w64-x86_64-python-zenmap-%.pkg.tar.zst: PKGBUILD
	makepkg-mingw -RdfL

dist/zenmap-w64-deletelog.txt: styrene.cfg
	styrene -p . -o $@ styrene.cfg --no-exe --no-zip

clean:
	rm -rf pkg/ src/ dist/ mingw-w64-*-package.log* mingw-w64-*.zst
