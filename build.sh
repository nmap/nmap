#/bin/sh

root_dir=$(pwd)
libssh2_dir=$root_dir/libssh2-1.7.0

echo "Compiling libssh2"
cd $libssh2_dir
mkdir BUILD
./configure --prefix=$libssh2_dir/BUILD
make && make install
echo "Compiled libssh2"

echo "Compiling nmap"
cd $root_dir
mkdir BUILD
./configure --prefix=$root_dir/BUILD --with-libssh2=$libssh2_dir/BUILD
make && make install
echo "Compiled nmap"


if [[ "$OSTYPE" == "darwin"* ]]; then 
	echo "Darwin is detected!";
	echo "Setting up executable's runtime running path"

	cd $root_dir/BUILD/bin
	
	install_name_tool -change $libssh2_dir/BUILD/lib/libssh2.1.dylib \
							  @loader_path/../../libssh2-1.7.0/BUILD/lib/libssh2.1.dylib \
							  nmap
fi

echo "Installation folder: $root_dir/BUILD"