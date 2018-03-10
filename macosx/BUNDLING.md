# Table of Contents
---
   
 * [Introduction](#intro)
 * [Jhbuild](#jhbuild)
 	* Observation
 	* Possible error
 * [gtk-mac-bundler](#bundler)
 * [How to use](#howto)
 	* Prerequisite
 	* Usage

## <a name="intro"></a> Introduction

On MacOS, you will need to install a few dependencies for bundling Nmap. You can follow the tutorial at [https://wiki.gnome.org/Projects/GTK%2B/OSX/Building](https://wiki.gnome.org/Projects/GTK%2B/OSX/Building) to build GTK-OSX and then continue reading here to install _gtk-mac-bundler_, or simply follow the following instructions.

## <a name="jhbuild"></a> Jhbuild

If at any point you decide that you want to start from fresh or to remove Jhbuild, just type the following command carefully (**recommand copy-paste** as the `rm` command may erase your startup disk with only a single typo!):

	$ rm -rf ~/bin/jhbuild ~/.local/bin/jhbuild ~/.local/share/jhbuild ~/.cache/jhbuild ~/.config/jhbuildrc ~/.jhbuildrc ~/.jhbuildrc-custom ~/jhbuild

1.	First, download the following script in your `$HOME` directory and run it — [https://git.gnome.org/browse/gtk-osx/plain/gtk-osx-build-setup.sh](https://git.gnome.org/browse/gtk-osx/plain/gtk-osx-build-setup.sh):

	~~~~
	$ sh $HOME/gtk-osx-build-setup.sh
	~~~~
	
	And add it to your `$PATH`, so you can run jhbuild without the absolute path (note that if you add this line to your `$HOME/.bash_profile` config file, you won't have to type this command every time your start a new terminal):
	
	~~~~
	$ export PATH=$HOME/.local/bin:$PATH
	~~~~
	
2.	Then,

	~~~~
	$ jhbuild bootstrap
	$ jhbuild build python meta-gtk-osx-bootstrap meta-gtk-osx-gtk3 meta-gtk-osx-python
	~~~~
	
	To install missing dependencies (with `--force` option to force rebuilding).	
	If you have errors, look for the dependency name (for example glib) and install it using homebrew. Then run the command again.

### Possible error

For those of you who have this error while trying to make,

~~~~
svn: E155021: This client is too old to work with the working copy at...
~~~~

You need to **update SVN**.<br/>
Go to [http://www.wandisco.com/subversion/download#osx](http://www.wandisco.com/subversion/download#osx) and download and install the approriate version for your OS.

Now, add the path for the new SVN version to your `$PATH`:

~~~~
$ export PATH=/opt/subversion/bin:$PATH
~~~~

## <a name="bundler"></a> gtk-mac-bundler

Now that Jhbuild is installed, we can install **gtk-mac-bundler** which will be used to build the application bundle:

~~~~
$ git clone git://git.gnome.org/gtk-mac-bundler
$ cd gtk-mac-bundler
$ make install
~~~~

## <a name="howto"></a> How to use

#### Prerequisite:
`nmap/macosx/openssl.modules`: This is a jhbuild moduleset that can be used to build/update openssl, libapr and libsvn.

#### Usage:

Now use it like this:
    
~~~~
$ jhbuild -m openssl.modules build nmap-deps
~~~~