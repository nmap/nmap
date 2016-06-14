# Bundling

## Notes

This package contains Nmap, Zenmap, Ncat, Ndiff, and Nping. It is intended to work on Intel Macs running Mac OS X 10.8 or later.

Installation of all packages is optional. Unselect Zenmap to get just the command-line tool. Unselect Nmap if you prefer to use a copy of Nmap that is already installed. Zenmap will not work without Nmap.

The nmap, ncat, ndiff, and nping command-line binaries will be installed in `/usr/local/bin`, and additional support files will be installed in `/usr/local/share`. The Zenmap application bundle will be installed in `/Applications/Zenmap.app`.


## Jhbuild

In order to set up Jhbuild properly before building Nmap suite, follow the tutorial at [https://wiki.gnome.org/Projects/GTK%2B/OSX/Building](https://wiki.gnome.org/Projects/GTK%2B/OSX/Building), but keep reading this file if you encounter any error...

If you had any error, just type the following command to delete jhbuild,

	$ rm -rf ~/bin/jhbuild ~/.local/bin/jhbuild ~/.local/share/jhbuild ~/.cache/jhbuild ~/.config/jhbuildrc ~/.jhbuildrc ~/jhbuild

And we'll start over together:

1.	First, simply download the following script in your _$HOME_ directory and launch it ([https://git.gnome.org/browse/gtk-osx/plain/gtk-osx-build-setup.sh](https://git.gnome.org/browse/gtk-osx/plain/gtk-osx-build-setup.sh)):

	~~~~
	$ sh gtk-osx-build-setup.sh
	~~~~
	
	And add it to your _$PATH_, so you can run jhbuild without the absolute path:
	
	~~~~
	$ export PATH=$HOME/.local/bin:$PATH
	~~~~
	
2.	In `~/.jhbuildrc-custom`, make sure that this line is setup properly:

	~~~~
	setup_sdk(target=_target, sdk_version="native", architectures=["i386"])
	~~~~
	
	for an i386 architecture.
	
3.	Now do,

	~~~~
	$ jhbuild bootstrap
	~~~~
	
	To install missing dependencies (with **--force** option to force rebuilding).<br/>Go to **Observation** if errors appear...
	
4.	And,

	~~~~
	$ jhbuild build meta-gtk-osx-bootstrap
	$ jhbuild build meta-gtk-osx-core
	~~~~
	
	Go to **Observation** if errors appear... 
	
<br/>
### Observation
	
If anything goes wrong now, it'll probably be a bad link on your python binary, so check that you're using the **GTK one** instead of the original mac one:

~~~~	
$ jhbuild shell
bash$ which python
~~~~

If you can see _gtk_ in the path, everything is fine with Python, else do:

~~~~
$ jhbuild build --force python
~~~~

And make an alias, to use this version of Python with Jhbuild:

~~~~
$ alias jhbuild="PATH=gtk-prefix/bin:$PATH jhbuild"
~~~~

Now continue at **step 3** with the --force option at the end of each command, to reinstall everything from scratch with this new python binary.

### Possible error

For those of you who have this error while trying to make,

~~~~
svn: E155021: This client is too old to work with the working copy at...
~~~~

You need to **update SVN**.<br/>
Go to [http://www.wandisco.com/subversion/download#osx](http://www.wandisco.com/subversion/download#osx) and download and install the approriate version for your OS.

Now, add the path for the new SVN version to your _$PATH_:

~~~~
$ export PATH=/opt/subversion/bin:$PATH
~~~~


## Jhbuild & gtk-mac-bundler

Now that Jhbuild is properly configured, we need to install **gtk-mac-bundler** in order to render the bundle file:

~~~~
$ git clone git://git.gnome.org/gtk-mac-bundler
$ cd gtk-mac-bundler
$ make install
~~~~

## How to use
#### Prerequisite:
—`openssl.modules`:

This is a jhbuild moduleset that can be used to build/update openssl, libapr and libsvn.
First, locate this part in your Jhbuild `~/.jhbuildrc` configuration file:

~~~~
if not _host_tiger:
    skip.append('make')
    skip.append('subversion')
~~~~

And comment this line with a #: 

~~~~
if not _host_tiger:
    skip.append('make')
	# skip.append('subversion')
~~~~

This will **stop Jhbuild from ignoring subversion**, which was in the ignore list.

#### Usage:

Now use it like this:
    
~~~~
$ jhbuild -m openssl.modules build nmap-deps
~~~~