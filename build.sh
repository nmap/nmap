#/bin/sh

root_dir=$(pwd)
libssh2_dir=$root_dir/libssh2-1.7.0

mkdir log
log_dir=$root_dir/log

echo "Compiling libssh2"
cd $libssh2_dir
mkdir BUILD
./configure --prefix=$libssh2_dir/BUILD > $log_dir/libssh2_configure.log
make > $log_dir/libssh2_make.log
make install > $log_dir/libssh2_make_install.log
echo "Compiled libssh2"

echo "Compiling nmap"
cd $root_dir
mkdir BUILD
./configure --prefix=$root_dir/BUILD --with-libssh2=$libssh2_dir/BUILD > $log_dir/nmap_configure.log
make > $log_dir/nmap_make.log 
make install > $log_dir/nmap_make_install.log
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
echo "Log folder: $log_dir"

echo "\nGood Luck!"